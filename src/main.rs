// Parser
#[macro_use]
extern crate nom;
pub mod parser;

// Main
use std::collections::HashMap;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::prelude::*;
use std::io::Write;
use std::path::Path;
use std::str;

const VERSION: Option<&'static str> = option_env!("CARGO_PKG_VERSION");

fn main() {
    // Obtain program arguments
    let mut args = std::env::args_os();

    // Check if we have none
    if args.len() <= 1 {
        println!("IFRExtractor RS v{} - extracts HII database from binary files into human-readable text\nUsage: ifrextractor file.bin", 
        VERSION.unwrap_or("0.0.0"));
        std::process::exit(1);
    }

    // The only expected argument is a path to input file
    let arg = args.nth(1).expect("Failed to obtain file path");
    let path = Path::new(&arg);

    // Open input file
    let mut file = File::open(&path).expect("Can't open input file");

    // Read the whole file as binary data
    let mut data = Vec::new();
    file.read_to_end(&mut data).expect("Can't read input file");

    // Find all string and form packages
    let mut string_id_maps: Vec<HashMap<u16, String>> = Vec::new();
    find_string_and_form_packages(path.as_os_str(), &data, &mut string_id_maps);

    // Call extraction function
    ifr_extract(path.as_os_str(), &data);
}

fn find_string_and_form_packages(path: &OsStr, data: &[u8], string_id_maps: &mut Vec<HashMap<u16, String>>) -> () {
    let mut text = Vec::new(); // Output text

    //
    // Search for all string packages in the input file
    //
    let mut i = 0;
    while i < data.len() {
        if let Ok((_, candidate)) = parser::hii_string_package_candidate(&data[i..]) {
            if let Ok((_, package)) = parser::hii_package(candidate) {
                if let Ok((_, string_package)) = parser::hii_string_package(package.Data.unwrap()) {
                    write!(
                        &mut text,
                        "HII string package: Offset: 0x{:X}, Length: 0x{:X}, Language: {}, ",
                        i,
                        candidate.len(),
                        string_package.Language
                    )
                    .unwrap();
                    i += candidate.len();

                    let mut string_id_map = HashMap::new(); // Map of StringIds to strings

                    //
                    // Parse SIBT blocks
                    //
                    match parser::hii_sibt_blocks(string_package.Data) {
                        Ok((_, sibt_blocks)) => {
                            string_id_map.insert(0 as u16, String::new());
                            let mut current_string_index = 1;
                            for block in &sibt_blocks {
                                match block.Type {
                                    // 0x00: End
                                    parser::HiiSibtType::End => {}
                                    // 0x10: StringScsu
                                    parser::HiiSibtType::StringScsu => {
                                        if let Ok((_, string)) =
                                            parser::sibt_string_scsu(block.Data.unwrap())
                                        {
                                            string_id_map.insert(current_string_index, string);
                                            current_string_index += 1;
                                        }
                                    }
                                    // 0x11: StringScsuFont
                                    parser::HiiSibtType::StringScsuFont => {
                                        if let Ok((_, string)) =
                                            parser::sibt_string_scsu_font(block.Data.unwrap())
                                        {
                                            string_id_map.insert(current_string_index, string);
                                            current_string_index += 1;
                                        }
                                    }
                                    // 0x12: StringsScsu
                                    parser::HiiSibtType::StringsScsu => {
                                        if let Ok((_, strings)) =
                                            parser::sibt_strings_scsu(block.Data.unwrap())
                                        {
                                            for string in strings {
                                                string_id_map.insert(current_string_index, string);
                                                current_string_index += 1;
                                            }
                                        }
                                    }
                                    // 0x13: StringsScsuFont
                                    parser::HiiSibtType::StringsScsuFont => {
                                        if let Ok((_, strings)) =
                                            parser::sibt_strings_scsu_font(block.Data.unwrap())
                                        {
                                            for string in strings {
                                                string_id_map.insert(current_string_index, string);
                                                current_string_index += 1;
                                            }
                                        }
                                    }
                                    // 0x14: StringUcs2
                                    parser::HiiSibtType::StringUcs2 => {
                                        if let Ok((_, string)) =
                                            parser::sibt_string_ucs2(block.Data.unwrap())
                                        {
                                            string_id_map.insert(current_string_index, string);
                                            current_string_index += 1;
                                        }
                                    }
                                    // 0x15: StringUcs2Font
                                    parser::HiiSibtType::StringUcs2Font => {
                                        if let Ok((_, string)) =
                                            parser::sibt_string_ucs2_font(block.Data.unwrap())
                                        {
                                            string_id_map.insert(current_string_index, string);
                                            current_string_index += 1;
                                        }
                                    }
                                    // 0x16: StringsUcs2
                                    parser::HiiSibtType::StringsUcs2 => {
                                        if let Ok((_, strings)) =
                                            parser::sibt_strings_ucs2(block.Data.unwrap())
                                        {
                                            for string in strings {
                                                string_id_map.insert(current_string_index, string);
                                                current_string_index += 1;
                                            }
                                        }
                                    }
                                    // 0x17: StringsUcs2Font
                                    parser::HiiSibtType::StringsUcs2Font => {
                                        if let Ok((_, strings)) =
                                            parser::sibt_strings_ucs2_font(block.Data.unwrap())
                                        {
                                            for string in strings {
                                                string_id_map.insert(current_string_index, string);
                                                current_string_index += 1;
                                            }
                                        }
                                    }
                                    // 0x20: Duplicate
                                    parser::HiiSibtType::Duplicate => {
                                        current_string_index += 1;
                                    }
                                    // 0x21: Skip2
                                    parser::HiiSibtType::Skip2 => {
                                        // Manual parsing of Data as u16
                                        let count = block.Data.unwrap();
                                        current_string_index +=
                                            count[0] as u16 + 0x100 * count[1] as u16;
                                    }
                                    // 0x22: Skip1
                                    parser::HiiSibtType::Skip1 => {
                                        // Manual parsing of Data as u8
                                        let count = block.Data.unwrap();
                                        current_string_index += count[0] as u16;
                                    }
                                    // Blocks below don't have any strings nor can they influence current_string_index
                                    // No need to parse them here
                                    // 0x30: Ext1
                                    parser::HiiSibtType::Ext1 => {}
                                    // 0x31: Ext2
                                    parser::HiiSibtType::Ext2 => {}
                                    // 0x32: Ext4
                                    parser::HiiSibtType::Ext4 => {}
                                    // Unknown SIBT block is impossible, because parsing will fail on it due to it's unknown length
                                    parser::HiiSibtType::Unknown(_) => {}
                                }
                            }

                            //
                            // Summarise string package parsing results
                            //
                            writeln!(&mut text, "Strings: {}", string_id_map.len()).unwrap();
                            string_id_maps.push(string_id_map);

                        }
                        Err(_) => {}
                    }
                } else {
                    i += 1;
                }
            } else {
                i += 1;
            }
        } else {
            i += 1;
        }
    }

    //
    // Search for all form packages in the input file
    //
    i = 0;
    while i < data.len() {
        if let Ok((_, candidate)) = parser::hii_form_package_candidate(&data[i..]) {
            if let Ok((_, package)) = parser::hii_package(candidate) {
                write!(
                    &mut text,
                    "HII form package: Offset: 0x{:X}, Length: 0x{:X}, ",
                    i,
                    candidate.len()
                )
                .unwrap();
                i += candidate.len();

                //
                // Parse form package and obtain StringIds
                //
                let mut string_ids: Vec<u16> = Vec::new(); // Output text
                match parser::ifr_operations(package.Data.unwrap()) {
                    Ok((_, operations)) => {
                        //let mut current_operation: usize = 0;
                        for operation in &operations {
                            //current_operation += 1;
                            //println!("Operation #{}, OpCode: {:?}, Length 0x{:X}, ScopeStart: {}", current_operation, operation.OpCode, operation.Length, operation.ScopeStart).unwrap();
                            match operation.OpCode {
                                // 0x01: Form
                                parser::IfrOpcode::Form => {
                                    match parser::ifr_form(operation.Data.unwrap()) {
                                        Ok((_, form)) => {
                                            string_ids.push(form.TitleStringId);
                                        }
                                        Err(_) => {}
                                    }
                                }
                                // 0x02: Subtitle
                                parser::IfrOpcode::Subtitle => {
                                    match parser::ifr_subtitle(operation.Data.unwrap()) {
                                        Ok((_, sub)) => {
                                            string_ids.push(sub.PromptStringId);
                                            string_ids.push(sub.HelpStringId);
                                        }
                                        Err(_) => {}
                                    }
                                }
                                // 0x03: Text
                                parser::IfrOpcode::Text => {
                                    match parser::ifr_text(operation.Data.unwrap()) {
                                        Ok((_, txt)) => {
                                            string_ids.push(txt.PromptStringId);
                                            string_ids.push(txt.HelpStringId);
                                            string_ids.push(txt.TextId);
                                        }
                                        Err(_) => {}
                                    }
                                }
                                // 0x04: Image
                                parser::IfrOpcode::Image => {}
                                // 0x05: OneOf
                                parser::IfrOpcode::OneOf => {
                                    match parser::ifr_one_of(operation.Data.unwrap()) {
                                        Ok((_, onf)) => {
                                            string_ids.push(onf.PromptStringId);
                                            string_ids.push(onf.HelpStringId);
                                        }
                                        Err(_) => {}
                                    }
                                }
                                // 0x06: CheckBox
                                parser::IfrOpcode::CheckBox => {
                                    match parser::ifr_check_box(operation.Data.unwrap()) {
                                        Ok((_, cb)) => {
                                            string_ids.push(cb.PromptStringId);
                                            string_ids.push(cb.HelpStringId);
                                        }
                                        Err(_) => {}
                                    }
                                }
                                // 0x07: Numeric
                                parser::IfrOpcode::Numeric => {
                                    match parser::ifr_numeric(operation.Data.unwrap()) {
                                        Ok((_, num)) => {
                                            string_ids.push(num.PromptStringId);
                                            string_ids.push(num.HelpStringId);
                                        }
                                        Err(_) => {}
                                    }
                                }
                                // 0x08: Password
                                parser::IfrOpcode::Password => {
                                    match parser::ifr_password(operation.Data.unwrap()) {
                                        Ok((_, pw)) => {
                                            string_ids.push(pw.PromptStringId);
                                            string_ids.push(pw.HelpStringId);
                                        }
                                        Err(_) => {}
                                    }
                                }
                                // 0x09: OneOfOption
                                parser::IfrOpcode::OneOfOption => {
                                    match parser::ifr_one_of_option(operation.Data.unwrap()) {
                                        Ok((_, opt)) => {
                                            string_ids.push(opt.OptionStringId);
                                            match opt.Value {
                                                parser::IfrTypeValue::String(x) => {
                                                    string_ids.push(x);
                                                }
                                                parser::IfrTypeValue::Action(x) => {
                                                    string_ids.push(x);
                                                }
                                                _ => {}
                                            }
                                        }
                                        Err(_) => {}
                                    }
                                }
                                // 0x0A: SuppressIf
                                parser::IfrOpcode::SuppressIf => {}
                                // 0x0B: Locked
                                parser::IfrOpcode::Locked => {}
                                // 0x0C: Action
                                parser::IfrOpcode::Action => {
                                    match parser::ifr_action(operation.Data.unwrap()) {
                                        Ok((_, act)) => {
                                            string_ids.push(act.PromptStringId);
                                            string_ids.push(act.HelpStringId);
                                            if let Some(x) = act.ConfigStringId {
                                                string_ids.push(x);
                                            }
                                        }
                                        Err(_) => {}
                                    }
                                }
                                // 0x0D: ResetButton
                                parser::IfrOpcode::ResetButton => {
                                    match parser::ifr_reset_button(operation.Data.unwrap()) {
                                        Ok((_, rst)) => {
                                            string_ids.push(rst.PromptStringId);
                                            string_ids.push(rst.HelpStringId);
                                        }
                                        Err(_) => {}
                                    }
                                }
                                // 0x0E: FormSet
                                parser::IfrOpcode::FormSet => {
                                    match parser::ifr_form_set(operation.Data.unwrap()) {
                                        Ok((_, form_set)) => {
                                            string_ids.push(form_set.TitleStringId);
                                            string_ids.push(form_set.HelpStringId);
                                        }
                                        Err(_) => {}
                                    }
                                }
                                // 0x0F: Ref
                                parser::IfrOpcode::Ref => {
                                    match parser::ifr_ref(operation.Data.unwrap()) {
                                        Ok((_, rf)) => {
                                            string_ids.push(rf.PromptStringId);
                                            string_ids.push(rf.HelpStringId);
                                        }
                                        Err(_) => {}
                                    }
                                }
                                // 0x10: NoSubmitIf
                                parser::IfrOpcode::NoSubmitIf => {
                                    match parser::ifr_no_submit_if(operation.Data.unwrap()) {
                                        Ok((_, ns)) => {
                                            string_ids.push(ns.ErrorStringId);
                                        }
                                        Err(_) => {}
                                    }
                                }
                                // 0x11: InconsistentIf
                                parser::IfrOpcode::InconsistentIf => {
                                    match parser::ifr_inconsistent_if(operation.Data.unwrap()) {
                                        Ok((_, inc)) => {
                                            string_ids.push(inc.ErrorStringId);
                                        }
                                        Err(_) => {}
                                    }
                                }
                                // 0x12: EqIdVal
                                parser::IfrOpcode::EqIdVal => {}
                                // 0x13: EqIdId
                                parser::IfrOpcode::EqIdId => {}
                                // 0x14: EqIdValList
                                parser::IfrOpcode::EqIdValList => {}
                                // 0x15: And
                                parser::IfrOpcode::And => {}
                                // 0x16: Or
                                parser::IfrOpcode::Or => {}
                                // 0x17: Not
                                parser::IfrOpcode::Not => {}
                                // 0x18: Rule
                                parser::IfrOpcode::Rule => {}
                                // 0x19: GrayOutIf
                                parser::IfrOpcode::GrayOutIf => {}
                                // 0x1A: Date
                                parser::IfrOpcode::Date => {
                                    match parser::ifr_date(operation.Data.unwrap()) {
                                        Ok((_, dt)) => {
                                            string_ids.push(dt.PromptStringId);
                                            string_ids.push(dt.HelpStringId);
                                        }
                                        Err(_) => {}
                                    }
                                }
                                // 0x1B: Time
                                parser::IfrOpcode::Time => {
                                    match parser::ifr_time(operation.Data.unwrap()) {
                                        Ok((_, time)) => {
                                            string_ids.push(time.PromptStringId);
                                            string_ids.push(time.HelpStringId);
                                        }
                                        Err(_) => {}
                                    }
                                }
                                // 0x1C: String
                                parser::IfrOpcode::String => {
                                    match parser::ifr_string(operation.Data.unwrap()) {
                                        Ok((_, st)) => {
                                            string_ids.push(st.PromptStringId);
                                            string_ids.push(st.HelpStringId);
                                        }
                                        Err(_) => {}
                                    }
                                }
                                // 0x1D: Refresh
                                parser::IfrOpcode::Refresh => {}
                                // 0x1E: DisableIf
                                parser::IfrOpcode::DisableIf => {}
                                // 0x1F: Animation
                                parser::IfrOpcode::Animation => {}
                                // 0x20: ToLower
                                parser::IfrOpcode::ToLower => {}
                                // 0x21: ToUpper
                                parser::IfrOpcode::ToUpper => {}
                                // 0x22: Map
                                parser::IfrOpcode::Map => {}
                                // 0x23: OrderedList
                                parser::IfrOpcode::OrderedList => {
                                    match parser::ifr_ordered_list(operation.Data.unwrap()) {
                                        Ok((_, ol)) => {
                                            string_ids.push(ol.PromptStringId);
                                            string_ids.push(ol.HelpStringId);
                                        }
                                        Err(_) => {}
                                    }
                                }
                                // 0x24: VarStore
                                parser::IfrOpcode::VarStore => {}
                                // 0x25: VarStoreNameValue
                                parser::IfrOpcode::VarStoreNameValue => {}
                                // 0x26: VarStoreEfi258
                                parser::IfrOpcode::VarStoreEfi => {}
                                // 0x27: VarStoreDevice
                                parser::IfrOpcode::VarStoreDevice => {
                                    match parser::ifr_var_store_device(operation.Data.unwrap()) {
                                        Ok((_, var_store)) => {
                                            string_ids.push(var_store.DevicePathStringId);
                                        }
                                        Err(_) => {}
                                    }
                                }
                                // 0x28: Version
                                parser::IfrOpcode::Version => {}
                                // 0x29: End
                                parser::IfrOpcode::End => {}
                                // 0x2A: Match
                                parser::IfrOpcode::Match => {}
                                // 0x2B: Get
                                parser::IfrOpcode::Get => {}
                                // 0x2C: Set
                                parser::IfrOpcode::Set => {}
                                // 0x2D: Read
                                parser::IfrOpcode::Read => {}
                                // 0x2E: Write
                                parser::IfrOpcode::Write => {}
                                // 0x2F: Equal
                                parser::IfrOpcode::Equal => {}
                                // 0x30: NotEqual
                                parser::IfrOpcode::NotEqual => {}
                                // 0x31: GreaterThan
                                parser::IfrOpcode::GreaterThan => {}
                                // 0x32: GreaterEqual
                                parser::IfrOpcode::GreaterEqual => {}
                                // 0x33: LessThan
                                parser::IfrOpcode::LessThan => {}
                                // 0x34: LessEqual
                                parser::IfrOpcode::LessEqual => {}
                                // 0x35: BitwiseAnd
                                parser::IfrOpcode::BitwiseAnd => {}
                                // 0x36: BitwiseOr
                                parser::IfrOpcode::BitwiseOr => {}
                                // 0x37: BitwiseNot
                                parser::IfrOpcode::BitwiseNot => {}
                                // 0x38: ShiftLeft
                                parser::IfrOpcode::ShiftLeft => {}
                                // 0x39: ShiftRight
                                parser::IfrOpcode::ShiftRight => {}
                                // 0x3A: Add
                                parser::IfrOpcode::Add => {}
                                // 0x3B: Substract
                                parser::IfrOpcode::Substract => {}
                                // 0x3C: Multiply
                                parser::IfrOpcode::Multiply => {}
                                // 0x3D: Divide
                                parser::IfrOpcode::Divide => {}
                                // 0x3E: Modulo
                                parser::IfrOpcode::Modulo => {}
                                // 0x3F: RuleRef
                                parser::IfrOpcode::RuleRef => {}
                                // 0x40: QuestionRef1
                                parser::IfrOpcode::QuestionRef1 => {}
                                // 0x41: QuestionRef2
                                parser::IfrOpcode::QuestionRef2 => {}
                                // 0x42: Uint8
                                parser::IfrOpcode::Uint8 => {}
                                // 0x43: Uint16
                                parser::IfrOpcode::Uint16 => {}
                                // 0x44: Uint32
                                parser::IfrOpcode::Uint32 => {}
                                // 0x45: Uint64
                                parser::IfrOpcode::Uint64 => {}
                                // 0x46: True
                                parser::IfrOpcode::True => {}
                                // 0x47: False
                                parser::IfrOpcode::False => {}
                                // 0x48: ToUint
                                parser::IfrOpcode::ToUint => {}
                                // 0x49: ToString
                                parser::IfrOpcode::ToString => {}
                                // 0x4A: ToBoolean
                                parser::IfrOpcode::ToBoolean => {}
                                // 0x4B: Mid
                                parser::IfrOpcode::Mid => {}
                                // 0x4C: Find
                                parser::IfrOpcode::Find => {}
                                // 0x4D: Token
                                parser::IfrOpcode::Token => {}
                                // 0x4E: StringRef1
                                parser::IfrOpcode::StringRef1 => {
                                    match parser::ifr_string_ref_1(operation.Data.unwrap()) {
                                        Ok((_, st)) => {
                                            string_ids.push(st.StringId);
                                        }
                                        Err(_) => {}
                                    }
                                }
                                // 0x4F: StringRef2
                                parser::IfrOpcode::StringRef2 => {}
                                // 0x50: Conditional
                                parser::IfrOpcode::Conditional => {}
                                // 0x51: QuestionRef3
                                parser::IfrOpcode::QuestionRef3 => {
                                    if let Some(_) = operation.Data {
                                        match parser::ifr_question_ref_3(operation.Data.unwrap()) {
                                            Ok((_, qr)) => {
                                                if let Some(x) = qr.DevicePathId {
                                                    string_ids.push(x);
                                                }
                                            }
                                            Err(_) => {}
                                        }
                                    }
                                }
                                // 0x52: Zero
                                parser::IfrOpcode::Zero => {}
                                // 0x53: One
                                parser::IfrOpcode::One => {}
                                // 0x54: Ones
                                parser::IfrOpcode::Ones => {}
                                // 0x55: Undefined
                                parser::IfrOpcode::Undefined => {}
                                // 0x56: Length
                                parser::IfrOpcode::Length => {}
                                // 0x57: Dup
                                parser::IfrOpcode::Dup => {}
                                // 0x58: This
                                parser::IfrOpcode::This => {}
                                // 0x59: Span
                                parser::IfrOpcode::Span => {}
                                // 0x5A: Value
                                parser::IfrOpcode::Value => {}
                                // 0x5B: Default
                                parser::IfrOpcode::Default => {
                                    match parser::ifr_default(operation.Data.unwrap()) {
                                        Ok((_, def)) => match def.Value {
                                            parser::IfrTypeValue::String(x) => {
                                                string_ids.push(x);
                                            }
                                            parser::IfrTypeValue::Action(x) => {
                                                string_ids.push(x);
                                            }
                                            _ => {}
                                        },
                                        Err(_) => {}
                                    }
                                }
                                // 0x5C: DefaultStore
                                parser::IfrOpcode::DefaultStore => {
                                    match parser::ifr_default_store(operation.Data.unwrap()) {
                                        Ok((_, default_store)) => {
                                            string_ids.push(default_store.NameStringId);
                                        }
                                        Err(_) => {}
                                    }
                                }
                                // 0x5D: FormMap
                                parser::IfrOpcode::FormMap => {
                                    match parser::ifr_form_map(operation.Data.unwrap()) {
                                        Ok((_, form_map)) => {
                                            for method in form_map.Methods {
                                                string_ids.push(method.MethodTitleId);
                                            }
                                        }
                                        Err(_) => {}
                                    }
                                }
                                // 0x5E: Catenate
                                parser::IfrOpcode::Catenate => {}
                                // 0x5F: GUID
                                parser::IfrOpcode::Guid => {
                                    match parser::ifr_guid(operation.Data.unwrap()) {
                                        Ok((_, guid)) => {
                                            // This manual parsing here is ugly and can ultimately be done using nom,
                                            // but it's done already and not that important anyway
                                            // TODO: refactor later
                                            match guid.Guid {
                                                parser::IFR_TIANO_GUID => {
                                                    if let Ok((_, edk2)) =
                                                        parser::ifr_guid_edk2(guid.Data)
                                                    {
                                                        match edk2.ExtendedOpCode {
                                                            parser::IfrEdk2ExtendOpCode::Banner => {
                                                                if let Ok((_, banner)) = parser::ifr_guid_edk2_banner(edk2.Data) {
                                                                    string_ids.push(banner.TitleId);
                                                                }
                                                            }
                                                            parser::IfrEdk2ExtendOpCode::Label => {}
                                                            parser::IfrEdk2ExtendOpCode::Timeout => {}
                                                            parser::IfrEdk2ExtendOpCode::Class => {}
                                                            parser::IfrEdk2ExtendOpCode::SubClass => {}
                                                            parser::IfrEdk2ExtendOpCode::Unknown(_) => {}
                                                        }
                                                    }
                                                }
                                                parser::IFR_FRAMEWORK_GUID => {
                                                    if let Ok((_, edk)) =
                                                        parser::ifr_guid_edk(guid.Data)
                                                    {
                                                        match edk.ExtendedOpCode {
                                                            parser::IfrEdkExtendOpCode::OptionKey => {}
                                                            parser::IfrEdkExtendOpCode::VarEqName => {
                                                                if edk.Data.len() == 2 {
                                                                    let name_id = edk.Data[1] as u16 * 100 + edk.Data[0] as u16;
                                                                    string_ids.push(name_id);
                                                                }
                                                            }
                                                            parser::IfrEdkExtendOpCode::Unknown(_) => {}
                                                        }
                                                    }
                                                }
                                                _ => {}
                                            }
                                        }
                                        Err(_) => {}
                                    }
                                }
                                // 0x60: Security
                                parser::IfrOpcode::Security => {}
                                // 0x61: ModalTag
                                parser::IfrOpcode::ModalTag => {}
                                // 0x62: RefreshId
                                parser::IfrOpcode::RefreshId => {}
                                // 0x63: WarningIf
                                parser::IfrOpcode::WarningIf => {
                                    match parser::ifr_warning_if(operation.Data.unwrap()) {
                                        Ok((_, warn)) => {
                                            string_ids.push(warn.WarningStringId);
                                        }
                                        Err(_) => {}
                                    }
                                }
                                // 0x64: Match2
                                parser::IfrOpcode::Match2 => {}
                                // Unknown operation
                                parser::IfrOpcode::Unknown(_) => {}
                            }
                        }
                    }
                    Err(_) => {}
                }

                // Find min and max StringId, and the number of unique ones
                string_ids.sort();
                string_ids.dedup();
                if string_ids.len() > 0 {
                    writeln!(
                        &mut text,
                        "StringIds: Count: {}, Min: {}, Max: {}",
                        string_ids.len(),
                        string_ids.first().unwrap(),
                        string_ids.last().unwrap()
                    )
                    .unwrap();
                }
            } else {
                i += 1;
            }
        } else {
            i += 1;
        }
    }

    // Print the result
    if text.len() > 0 {
        println!(
            "{}\n{}",
            path.to_str().unwrap(),
            String::from_utf8_lossy(&text[..])
        );
    }
}

fn ifr_extract(path: &OsStr, data: &[u8]) -> () {
    let mut text = Vec::new(); // Output text
    let mut strings_map = HashMap::new(); // Map of StringIds to strings

    //
    // Search for all string packages in the input file
    // to build an ID to string map
    //
    let mut i = 0;
    while i < data.len() {
        if let Ok((_, candidate)) = parser::hii_string_package_candidate(&data[i..]) {
            if let Ok((_, package)) = parser::hii_package(candidate) {
                if let Ok((_, string_package)) = parser::hii_string_package(package.Data.unwrap()) {
                    write!(
                        &mut text,
                        "HII string package: Offset: 0x{:X}, Length: 0x{:X}, Language: {}",
                        i,
                        candidate.len(),
                        string_package.Language
                    )
                    .unwrap();
                    i += candidate.len();

                    // Skip languages other than English for now
                    if string_package.Language != "en-US" {
                        writeln!(&mut text, ", skipped").unwrap();
                        continue;
                    }
                    // Ask to split the input file if multiple string packages for English are found
                    // TODO: improve this
                    if strings_map.len() > 0 {
                        // TODO: some heuristics might be applied here to perform the split automatically
                        //       but they require a different, less generic way to search for HII packages
                        println!(
                            "Second HII string package of the same language found at offset 0x{:X}
There is no way for this program to determine what package will be used for a given form
Consider splitting the input file",
                            i - candidate.len()
                        );
                        std::process::exit(3);
                    }
                    writeln!(&mut text, "").unwrap();

                    // Parse SIBT blocks
                    match parser::hii_sibt_blocks(string_package.Data) {
                        Ok((_, sibt_blocks)) => {
                            strings_map.insert(0 as u16, String::new());
                            let mut current_string_index = 1;
                            for block in &sibt_blocks {
                                match block.Type {
                                    // 0x00: End
                                    parser::HiiSibtType::End => {}
                                    // 0x10: StringScsu
                                    parser::HiiSibtType::StringScsu => {
                                        if let Ok((_, string)) =
                                            parser::sibt_string_scsu(block.Data.unwrap())
                                        {
                                            strings_map.insert(current_string_index, string);
                                            current_string_index += 1;
                                        }
                                    }
                                    // 0x11: StringScsuFont
                                    parser::HiiSibtType::StringScsuFont => {
                                        if let Ok((_, string)) =
                                            parser::sibt_string_scsu_font(block.Data.unwrap())
                                        {
                                            strings_map.insert(current_string_index, string);
                                            current_string_index += 1;
                                        }
                                    }
                                    // 0x12: StringsScsu
                                    parser::HiiSibtType::StringsScsu => {
                                        if let Ok((_, strings)) =
                                            parser::sibt_strings_scsu(block.Data.unwrap())
                                        {
                                            for string in strings {
                                                strings_map.insert(current_string_index, string);
                                                current_string_index += 1;
                                            }
                                        }
                                    }
                                    // 0x13: StringsScsuFont
                                    parser::HiiSibtType::StringsScsuFont => {
                                        if let Ok((_, strings)) =
                                            parser::sibt_strings_scsu_font(block.Data.unwrap())
                                        {
                                            for string in strings {
                                                strings_map.insert(current_string_index, string);
                                                current_string_index += 1;
                                            }
                                        }
                                    }
                                    // 0x14: StringUcs2
                                    parser::HiiSibtType::StringUcs2 => {
                                        if let Ok((_, string)) =
                                            parser::sibt_string_ucs2(block.Data.unwrap())
                                        {
                                            strings_map.insert(current_string_index, string);
                                            current_string_index += 1;
                                        }
                                    }
                                    // 0x15: StringUcs2Font
                                    parser::HiiSibtType::StringUcs2Font => {
                                        if let Ok((_, string)) =
                                            parser::sibt_string_ucs2_font(block.Data.unwrap())
                                        {
                                            strings_map.insert(current_string_index, string);
                                            current_string_index += 1;
                                        }
                                    }
                                    // 0x16: StringsUcs2
                                    parser::HiiSibtType::StringsUcs2 => {
                                        if let Ok((_, strings)) =
                                            parser::sibt_strings_ucs2(block.Data.unwrap())
                                        {
                                            for string in strings {
                                                strings_map.insert(current_string_index, string);
                                                current_string_index += 1;
                                            }
                                        }
                                    }
                                    // 0x17: StringsUcs2Font
                                    parser::HiiSibtType::StringsUcs2Font => {
                                        if let Ok((_, strings)) =
                                            parser::sibt_strings_ucs2_font(block.Data.unwrap())
                                        {
                                            for string in strings {
                                                strings_map.insert(current_string_index, string);
                                                current_string_index += 1;
                                            }
                                        }
                                    }
                                    // 0x20: Duplicate
                                    parser::HiiSibtType::Duplicate => {
                                        current_string_index += 1;
                                    }
                                    // 0x21: Skip2
                                    parser::HiiSibtType::Skip2 => {
                                        // Manual parsing of Data as u16
                                        let count = block.Data.unwrap();
                                        current_string_index +=
                                            count[0] as u16 + 0x100 * count[1] as u16;
                                    }
                                    // 0x22: Skip1
                                    parser::HiiSibtType::Skip1 => {
                                        // Manual parsing of Data as u8
                                        let count = block.Data.unwrap();
                                        current_string_index += count[0] as u16;
                                    }
                                    // Blocks below don't have any strings nor can they influence current_string_index
                                    // No need to parse them here
                                    // 0x30: Ext1
                                    parser::HiiSibtType::Ext1 => {}
                                    // 0x31: Ext2
                                    parser::HiiSibtType::Ext2 => {}
                                    // 0x32: Ext4
                                    parser::HiiSibtType::Ext4 => {}
                                    // Unknown SIBT block is impossible, because parsing will fail on it due to it's unknown length
                                    parser::HiiSibtType::Unknown(_) => {}
                                }
                            }
                        }
                        Err(e) => {
                            println!("HII SIBT blocks parse error: {:?}", e);
                        }
                    }
                } else {
                    i += 1;
                }
            } else {
                i += 1;
            }
        } else {
            i += 1;
        }
    }

    //
    // Search for all form packages in the input file
    // using the constructed ID to string map
    //
    if strings_map.len() == 0 {
        println!("No string packages were found in the input file");
        std::process::exit(2);
    }

    i = 0;
    while i < data.len() {
        if let Ok((_, candidate)) = parser::hii_form_package_candidate(&data[i..]) {
            if let Ok((_, package)) = parser::hii_package(candidate) {
                writeln!(
                    &mut text,
                    "HII form package: Offset 0x{:X}, Length: 0x{:X}",
                    i,
                    candidate.len()
                )
                .unwrap();
                i += candidate.len();

                // Parse form package and output its structure as human-readable strings
                match parser::ifr_operations(package.Data.unwrap()) {
                    Ok((_, operations)) => {
                        let mut scope_depth = 1;
                        for operation in &operations {
                            if operation.OpCode == parser::IfrOpcode::End {
                                if scope_depth >= 1 {
                                    scope_depth -= 1;
                                }
                            }

                            write!(
                                &mut text,
                                "{:\t<1$}{2:?} ",
                                "", scope_depth, operation.OpCode
                            )
                            .unwrap();

                            match operation.OpCode {
                                // 0x01: Form
                                parser::IfrOpcode::Form => {
                                    match parser::ifr_form(operation.Data.unwrap()) {
                                        Ok((_, form)) => {
                                            write!(
                                                &mut text,
                                                "FormId: {}, Title: \"{}\"",
                                                form.FormId,
                                                strings_map
                                                    .get(&form.TitleStringId)
                                                    .unwrap_or(&String::from("InvalidId"))
                                            )
                                            .unwrap();
                                        }
                                        Err(e) => {
                                            write!(
                                                &mut text,
                                                "RawData: {:?}",
                                                operation.Data.unwrap()
                                            )
                                            .unwrap();
                                            println!("Form parse error: {:?}", e);
                                        }
                                    }
                                }
                                // 0x02: Subtitle
                                parser::IfrOpcode::Subtitle => {
                                    match parser::ifr_subtitle(operation.Data.unwrap()) {
                                        Ok((_, sub)) => {
                                            write!(
                                                &mut text,
                                                "Prompt: \"{}\", Help: \"{}\", Flags: 0x{:X}",
                                                strings_map
                                                    .get(&sub.PromptStringId)
                                                    .unwrap_or(&String::from("InvalidId")),
                                                strings_map
                                                    .get(&sub.HelpStringId)
                                                    .unwrap_or(&String::from("InvalidId")),
                                                sub.Flags
                                            )
                                            .unwrap();
                                        }
                                        Err(e) => {
                                            write!(
                                                &mut text,
                                                "RawData: {:?}",
                                                operation.Data.unwrap()
                                            )
                                            .unwrap();
                                            println!("Subtitle parse error: {:?}", e);
                                        }
                                    }
                                }
                                // 0x03: Text
                                parser::IfrOpcode::Text => {
                                    match parser::ifr_text(operation.Data.unwrap()) {
                                        Ok((_, txt)) => {
                                            write!(
                                                &mut text,
                                                "Prompt: \"{}\", Help: \"{}\", Text: \"{}\"",
                                                strings_map
                                                    .get(&txt.PromptStringId)
                                                    .unwrap_or(&String::from("InvalidId")),
                                                strings_map
                                                    .get(&txt.HelpStringId)
                                                    .unwrap_or(&String::from("InvalidId")),
                                                strings_map
                                                    .get(&txt.TextId)
                                                    .unwrap_or(&String::from("InvalidId"))
                                            )
                                            .unwrap();
                                        }
                                        Err(e) => {
                                            write!(
                                                &mut text,
                                                "RawData: {:?}",
                                                operation.Data.unwrap()
                                            )
                                            .unwrap();
                                            println!("Text parse error: {:?}", e);
                                        }
                                    }
                                }
                                // 0x04: Image
                                parser::IfrOpcode::Image => {
                                    match parser::ifr_image(operation.Data.unwrap()) {
                                        Ok((_, image)) => {
                                            write!(&mut text, "ImageId: {}", image.ImageId)
                                                .unwrap();
                                        }
                                        Err(e) => {
                                            write!(
                                                &mut text,
                                                "RawData: {:?}",
                                                operation.Data.unwrap()
                                            )
                                            .unwrap();
                                            println!("Iamge parse error: {:?}", e);
                                        }
                                    }
                                }
                                // 0x05: OneOf
                                parser::IfrOpcode::OneOf => {
                                    match parser::ifr_one_of(operation.Data.unwrap()) {
                                        Ok((_, onf)) => {
                                            write!(&mut text, "Prompt: \"{}\", Help: \"{}\", QuestionFlags: 0x{:X}, QuestionId: {}, VarStoreId: {}, VarStoreOffset: 0x{:X}, Flags: 0x{:X}, ", 
                                                strings_map.get(&onf.PromptStringId).unwrap_or(&String::from("InvalidId")),
                                                strings_map.get(&onf.HelpStringId).unwrap_or(&String::from("InvalidId")),
                                                onf.QuestionFlags,
                                                onf.QuestionId,
                                                onf.VarStoreId,
                                                onf.VarStoreInfo,
                                                onf.Flags).unwrap();
                                            if let Some(_) = onf.MinMaxStepData8[0] {
                                                write!(
                                                    &mut text,
                                                    "Min: {}, Max: {}, Step: {}",
                                                    onf.MinMaxStepData8[0].unwrap(),
                                                    onf.MinMaxStepData8[1].unwrap(),
                                                    onf.MinMaxStepData8[2].unwrap()
                                                )
                                                .unwrap();
                                            }
                                            if let Some(_) = onf.MinMaxStepData16[0] {
                                                write!(
                                                    &mut text,
                                                    "Min: {}, Max: {}, Step: {}",
                                                    onf.MinMaxStepData16[0].unwrap(),
                                                    onf.MinMaxStepData16[1].unwrap(),
                                                    onf.MinMaxStepData16[2].unwrap()
                                                )
                                                .unwrap();
                                            }
                                            if let Some(_) = onf.MinMaxStepData32[0] {
                                                write!(
                                                    &mut text,
                                                    "Min: {}, Max: {}, Step: {}",
                                                    onf.MinMaxStepData32[0].unwrap(),
                                                    onf.MinMaxStepData32[1].unwrap(),
                                                    onf.MinMaxStepData32[2].unwrap()
                                                )
                                                .unwrap();
                                            }
                                            if let Some(_) = onf.MinMaxStepData64[0] {
                                                write!(
                                                    &mut text,
                                                    "Min: {}, Max: {}, Step: {}",
                                                    onf.MinMaxStepData64[0].unwrap(),
                                                    onf.MinMaxStepData64[1].unwrap(),
                                                    onf.MinMaxStepData64[2].unwrap()
                                                )
                                                .unwrap();
                                            }
                                        }
                                        Err(e) => {
                                            write!(
                                                &mut text,
                                                "RawData: {:?}",
                                                operation.Data.unwrap()
                                            )
                                            .unwrap();
                                            println!("OneOf parse error: {:?}", e);
                                        }
                                    }
                                }
                                // 0x06: CheckBox
                                parser::IfrOpcode::CheckBox => {
                                    match parser::ifr_check_box(operation.Data.unwrap()) {
                                        Ok((_, cb)) => {
                                            write!(&mut text, "Prompt: \"{}\", Help: \"{}\", QuestionFlags: 0x{:X}, QuestionId: {}, VarStoreId: {}, VarStoreOffset: 0x{:X}, Flags: 0x{:X}", 
                                                strings_map.get(&cb.PromptStringId).unwrap_or(&String::from("InvalidId")),
                                                strings_map.get(&cb.HelpStringId).unwrap_or(&String::from("InvalidId")),
                                                cb.QuestionFlags,
                                                cb.QuestionId,
                                                cb.VarStoreId,
                                                cb.VarStoreInfo,
                                                cb.Flags).unwrap();
                                        }
                                        Err(e) => {
                                            write!(
                                                &mut text,
                                                "RawData: {:?}",
                                                operation.Data.unwrap()
                                            )
                                            .unwrap();
                                            println!("CheckBox parse error: {:?}", e);
                                        }
                                    }
                                }
                                // 0x07: Numeric
                                parser::IfrOpcode::Numeric => {
                                    match parser::ifr_numeric(operation.Data.unwrap()) {
                                        Ok((_, num)) => {
                                            write!(&mut text, "Prompt: \"{}\", Help: \"{}\", QuestionFlags: 0x{:X}, QuestionId: {}, VarStoreId: {}, VarStoreOffset: 0x{:X}, Flags: 0x{:X}, ", 
                                                strings_map.get(&num.PromptStringId).unwrap_or(&String::from("InvalidId")),
                                                strings_map.get(&num.HelpStringId).unwrap_or(&String::from("InvalidId")),
                                                num.QuestionFlags,
                                                num.QuestionId,
                                                num.VarStoreId,
                                                num.VarStoreInfo,
                                                num.Flags).unwrap();
                                            if let Some(_) = num.MinMaxStepData8[0] {
                                                write!(
                                                    &mut text,
                                                    "Min: {}, Max: {}, Step: {}",
                                                    num.MinMaxStepData8[0].unwrap(),
                                                    num.MinMaxStepData8[1].unwrap(),
                                                    num.MinMaxStepData8[2].unwrap()
                                                )
                                                .unwrap();
                                            }
                                            if let Some(_) = num.MinMaxStepData16[0] {
                                                write!(
                                                    &mut text,
                                                    "Min: {}, Max: {}, Step: {}",
                                                    num.MinMaxStepData16[0].unwrap(),
                                                    num.MinMaxStepData16[1].unwrap(),
                                                    num.MinMaxStepData16[2].unwrap()
                                                )
                                                .unwrap();
                                            }
                                            if let Some(_) = num.MinMaxStepData32[0] {
                                                write!(
                                                    &mut text,
                                                    "Min: {}, Max: {}, Step: {}",
                                                    num.MinMaxStepData32[0].unwrap(),
                                                    num.MinMaxStepData32[1].unwrap(),
                                                    num.MinMaxStepData32[2].unwrap()
                                                )
                                                .unwrap();
                                            }
                                            if let Some(_) = num.MinMaxStepData64[0] {
                                                write!(
                                                    &mut text,
                                                    "Min: {}, Max: {}, Step: {}",
                                                    num.MinMaxStepData64[0].unwrap(),
                                                    num.MinMaxStepData64[1].unwrap(),
                                                    num.MinMaxStepData64[2].unwrap()
                                                )
                                                .unwrap();
                                            }
                                        }
                                        Err(e) => {
                                            write!(
                                                &mut text,
                                                "RawData: {:?}",
                                                operation.Data.unwrap()
                                            )
                                            .unwrap();
                                            println!("Numeric parse error: {:?}", e);
                                        }
                                    }
                                }
                                // 0x08: Password
                                parser::IfrOpcode::Password => {
                                    match parser::ifr_password(operation.Data.unwrap()) {
                                        Ok((_, pw)) => {
                                            write!(&mut text, "Prompt: \"{}\", Help: \"{}\", QuestionFlags: 0x{:X}, QuestionId: {}, VarStoreId: {}, VarStoreInfo: 0x{:X}, MinSize: {}, MaxSize: {}", 
                                                strings_map.get(&pw.PromptStringId).unwrap_or(&String::from("InvalidId")),
                                                strings_map.get(&pw.HelpStringId).unwrap_or(&String::from("InvalidId")),
                                                pw.QuestionFlags,
                                                pw.QuestionId,
                                                pw.VarStoreId,
                                                pw.VarStoreInfo,
                                                pw.MinSize,
                                                pw.MaxSize).unwrap();
                                        }
                                        Err(e) => {
                                            write!(
                                                &mut text,
                                                "RawData: {:?}",
                                                operation.Data.unwrap()
                                            )
                                            .unwrap();
                                            println!("Password parse error: {:?}", e);
                                        }
                                    }
                                }
                                // 0x09: OneOfOption
                                parser::IfrOpcode::OneOfOption => {
                                    match parser::ifr_one_of_option(operation.Data.unwrap()) {
                                        Ok((_, opt)) => {
                                            write!(
                                                &mut text,
                                                "Option: \"{}\" ",
                                                strings_map
                                                    .get(&opt.OptionStringId)
                                                    .unwrap_or(&String::from("InvalidId"))
                                            )
                                            .unwrap();
                                            match opt.Value {
                                                parser::IfrTypeValue::String(x) => {
                                                    write!(
                                                        &mut text,
                                                        "String: \"{}\"",
                                                        strings_map
                                                            .get(&x)
                                                            .unwrap_or(&String::from("InvalidId"))
                                                    )
                                                    .unwrap();
                                                }
                                                parser::IfrTypeValue::Action(x) => {
                                                    write!(
                                                        &mut text,
                                                        "Action: \"{}\"",
                                                        strings_map
                                                            .get(&x)
                                                            .unwrap_or(&String::from("InvalidId"))
                                                    )
                                                    .unwrap();
                                                }
                                                _ => {
                                                    write!(&mut text, "Value: {}", opt.Value)
                                                        .unwrap();
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            write!(
                                                &mut text,
                                                "RawData: {:?}",
                                                operation.Data.unwrap()
                                            )
                                            .unwrap();
                                            println!("OneOfOption parse error: {:?}", e);
                                        }
                                    }
                                }
                                // 0x0A: SuppressIf
                                parser::IfrOpcode::SuppressIf => {}
                                // 0x0B: Locked
                                parser::IfrOpcode::Locked => {}
                                // 0x0C: Action
                                parser::IfrOpcode::Action => {
                                    match parser::ifr_action(operation.Data.unwrap()) {
                                        Ok((_, act)) => {
                                            write!(&mut text, "Prompt: \"{}\", Help: \"{}\", QuestionFlags: 0x{:X}, QuestionId: {}, VarStoreId: {}, VarStoreInfo: 0x{:X}", 
                                                strings_map.get(&act.PromptStringId).unwrap_or(&String::from("InvalidId")),
                                                strings_map.get(&act.HelpStringId).unwrap_or(&String::from("InvalidId")),
                                                act.QuestionFlags,
                                                act.QuestionId,
                                                act.VarStoreId,
                                                act.VarStoreInfo).unwrap();
                                            if let Some(x) = act.ConfigStringId {
                                                write!(
                                                    &mut text,
                                                    ", QuestionConfig: {}",
                                                    strings_map
                                                        .get(&x)
                                                        .unwrap_or(&String::from("InvalidId"))
                                                )
                                                .unwrap();
                                            }
                                        }
                                        Err(e) => {
                                            write!(
                                                &mut text,
                                                "RawData: {:?}",
                                                operation.Data.unwrap()
                                            )
                                            .unwrap();
                                            println!("Action parse error: {:?}", e);
                                        }
                                    }
                                }
                                // 0x0D: ResetButton
                                parser::IfrOpcode::ResetButton => {
                                    match parser::ifr_reset_button(operation.Data.unwrap()) {
                                        Ok((_, rst)) => {
                                            write!(
                                                &mut text,
                                                "Prompt: \"{}\", Help: \"{}\", DefaultId: {}",
                                                strings_map
                                                    .get(&rst.PromptStringId)
                                                    .unwrap_or(&String::from("InvalidId")),
                                                strings_map
                                                    .get(&rst.HelpStringId)
                                                    .unwrap_or(&String::from("InvalidId")),
                                                rst.DefaultId
                                            )
                                            .unwrap();
                                        }
                                        Err(e) => {
                                            write!(
                                                &mut text,
                                                "RawData: {:?}",
                                                operation.Data.unwrap()
                                            )
                                            .unwrap();
                                            println!("ResetButton parse error: {:?}", e);
                                        }
                                    }
                                }
                                // 0x0E: FormSet
                                parser::IfrOpcode::FormSet => {
                                    match parser::ifr_form_set(operation.Data.unwrap()) {
                                        Ok((_, form_set)) => {
                                            write!(
                                                &mut text,
                                                "GUID: {}, Title: \"{}\", Help: \"{}\"",
                                                form_set.Guid,
                                                strings_map
                                                    .get(&form_set.TitleStringId)
                                                    .unwrap_or(&String::from("InvalidId")),
                                                strings_map
                                                    .get(&form_set.HelpStringId)
                                                    .unwrap_or(&String::from("InvalidId"))
                                            )
                                            .unwrap();
                                        }
                                        Err(e) => {
                                            write!(
                                                &mut text,
                                                "RawData: {:?}",
                                                operation.Data.unwrap()
                                            )
                                            .unwrap();
                                            println!("FormSet parse error: {:?}", e);
                                        }
                                    }
                                }
                                // 0x0F: Ref
                                parser::IfrOpcode::Ref => {
                                    match parser::ifr_ref(operation.Data.unwrap()) {
                                        Ok((_, rf)) => {
                                            write!(&mut text, "Prompt: \"{}\", Help: \"{}\", QuestionFlags: 0x{:X}, QuestionId: {}, VarStoreId: {}, VarStoreInfo: 0x{:X} ", 
                                                strings_map.get(&rf.PromptStringId).unwrap_or(&String::from("InvalidId")),
                                                strings_map.get(&rf.HelpStringId).unwrap_or(&String::from("InvalidId")),
                                                rf.QuestionFlags,
                                                rf.QuestionId,
                                                rf.VarStoreId,
                                                rf.VarStoreInfo).unwrap();
                                            if let Some(x) = rf.FormId {
                                                write!(&mut text, ", FormId: {}", x).unwrap();
                                            }
                                            if let Some(x) = rf.RefQuestionId {
                                                write!(&mut text, ", RefQuestionId: {}", x)
                                                    .unwrap();
                                            }
                                            if let Some(x) = rf.FormSetGuid {
                                                write!(&mut text, ", FormSetGuid: {}", x).unwrap();
                                            }
                                            if let Some(x) = rf.DevicePathId {
                                                write!(&mut text, ", DevicePathId: {}", x).unwrap();
                                            }
                                        }
                                        Err(e) => {
                                            write!(
                                                &mut text,
                                                "RawData: {:?}",
                                                operation.Data.unwrap()
                                            )
                                            .unwrap();
                                            println!("Ref parse error: {:?}", e);
                                        }
                                    }
                                }
                                // 0x10: NoSubmitIf
                                parser::IfrOpcode::NoSubmitIf => {
                                    match parser::ifr_no_submit_if(operation.Data.unwrap()) {
                                        Ok((_, ns)) => {
                                            write!(
                                                &mut text,
                                                "Error: \"{}\"",
                                                strings_map
                                                    .get(&ns.ErrorStringId)
                                                    .unwrap_or(&String::from("InvalidId"))
                                            )
                                            .unwrap();
                                        }
                                        Err(e) => {
                                            write!(
                                                &mut text,
                                                "RawData: {:?}",
                                                operation.Data.unwrap()
                                            )
                                            .unwrap();
                                            println!("NoSubmitIf parse error: {:?}", e);
                                        }
                                    }
                                }
                                // 0x11: InconsistentIf
                                parser::IfrOpcode::InconsistentIf => {
                                    match parser::ifr_inconsistent_if(operation.Data.unwrap()) {
                                        Ok((_, inc)) => {
                                            write!(
                                                &mut text,
                                                "Error: \"{}\"",
                                                strings_map
                                                    .get(&inc.ErrorStringId)
                                                    .unwrap_or(&String::from("InvalidId"))
                                            )
                                            .unwrap();
                                        }
                                        Err(e) => {
                                            write!(
                                                &mut text,
                                                "RawData: {:?}",
                                                operation.Data.unwrap()
                                            )
                                            .unwrap();
                                            println!("InconsistentIf parse error: {:?}", e);
                                        }
                                    }
                                }
                                // 0x12: EqIdVal
                                parser::IfrOpcode::EqIdVal => {
                                    match parser::ifr_eq_id_val(operation.Data.unwrap()) {
                                        Ok((_, eq)) => {
                                            write!(
                                                &mut text,
                                                "QuestionId: {}, Value: {}",
                                                eq.QuestionId, eq.Value
                                            )
                                            .unwrap();
                                        }
                                        Err(e) => {
                                            write!(
                                                &mut text,
                                                "RawData: {:?}",
                                                operation.Data.unwrap()
                                            )
                                            .unwrap();
                                            println!(" EqIdVal parse error: {:?}", e);
                                        }
                                    }
                                }
                                // 0x13: EqIdId
                                parser::IfrOpcode::EqIdId => {
                                    match parser::ifr_eq_id_id(operation.Data.unwrap()) {
                                        Ok((_, eq)) => {
                                            write!(
                                                &mut text,
                                                "QuestionId: {}, OtherQuestionId: {}",
                                                eq.QuestionId, eq.OtherQuestionId
                                            )
                                            .unwrap();
                                        }
                                        Err(e) => {
                                            write!(
                                                &mut text,
                                                "RawData: {:?}",
                                                operation.Data.unwrap()
                                            )
                                            .unwrap();
                                            println!("EqIdId parse error: {:?}", e);
                                        }
                                    }
                                }
                                // 0x14: EqIdValList
                                parser::IfrOpcode::EqIdValList => {
                                    match parser::ifr_eq_id_val_list(operation.Data.unwrap()) {
                                        Ok((_, eql)) => {
                                            write!(
                                                &mut text,
                                                "QuestionId: {}, Values: {:?}",
                                                eql.QuestionId, eql.Values
                                            )
                                            .unwrap();
                                        }
                                        Err(e) => {
                                            write!(
                                                &mut text,
                                                "RawData: {:?}",
                                                operation.Data.unwrap()
                                            )
                                            .unwrap();
                                            println!("EqIdValList parse error: {:?}", e);
                                        }
                                    }
                                }
                                // 0x15: And
                                parser::IfrOpcode::And => {}
                                // 0x16: Or
                                parser::IfrOpcode::Or => {}
                                // 0x17: Not
                                parser::IfrOpcode::Not => {}
                                // 0x18: Rule
                                parser::IfrOpcode::Rule => {
                                    match parser::ifr_rule(operation.Data.unwrap()) {
                                        Ok((_, rule)) => {
                                            write!(&mut text, "RuleId: {}", rule.RuleId).unwrap();
                                        }
                                        Err(e) => {
                                            write!(
                                                &mut text,
                                                "RawData: {:?}",
                                                operation.Data.unwrap()
                                            )
                                            .unwrap();
                                            println!("Rule parse error: {:?}", e);
                                        }
                                    }
                                }
                                // 0x19: GrayOutIf
                                parser::IfrOpcode::GrayOutIf => {}
                                // 0x1A: Date
                                parser::IfrOpcode::Date => {
                                    match parser::ifr_date(operation.Data.unwrap()) {
                                        Ok((_, dt)) => {
                                            write!(&mut text, "Prompt: \"{}\", Help: \"{}\", QuestionFlags: 0x{:X}, QuestionId: {}, VarStoreId: {}, VarStoreInfo: 0x{:X}, Flags: 0x{:X}", 
                                                strings_map.get(&dt.PromptStringId).unwrap_or(&String::from("InvalidId")),
                                                strings_map.get(&dt.HelpStringId).unwrap_or(&String::from("InvalidId")),
                                                dt.QuestionFlags,
                                                dt.QuestionId,
                                                dt.VarStoreId,
                                                dt.VarStoreInfo,
                                                dt.Flags).unwrap();
                                        }
                                        Err(e) => {
                                            write!(
                                                &mut text,
                                                "RawData: {:?}",
                                                operation.Data.unwrap()
                                            )
                                            .unwrap();
                                            println!("Date parse error: {:?}", e);
                                        }
                                    }
                                }
                                // 0x1B: Time
                                parser::IfrOpcode::Time => {
                                    match parser::ifr_time(operation.Data.unwrap()) {
                                        Ok((_, time)) => {
                                            write!(&mut text, "Prompt: \"{}\", Help: \"{}\", QuestionFlags: 0x{:X}, QuestionId: {}, VarStoreId: {}, VarStoreInfo: 0x{:X}, Flags: 0x{:X}", 
                                                strings_map.get(&time.PromptStringId).unwrap_or(&String::from("InvalidId")),
                                                strings_map.get(&time.HelpStringId).unwrap_or(&String::from("InvalidId")),
                                                time.QuestionFlags,
                                                time.QuestionId,
                                                time.VarStoreId,
                                                time.VarStoreInfo,
                                                time.Flags).unwrap();
                                        }
                                        Err(e) => {
                                            write!(
                                                &mut text,
                                                "RawData: {:?}",
                                                operation.Data.unwrap()
                                            )
                                            .unwrap();
                                            println!("Time parse error: {:?}", e);
                                        }
                                    }
                                }
                                // 0x1C: String
                                parser::IfrOpcode::String => {
                                    match parser::ifr_string(operation.Data.unwrap()) {
                                        Ok((_, st)) => {
                                            write!(&mut text, "Prompt: \"{}\", Help: \"{}\", QuestionFlags: 0x{:X}, QuestionId: {}, VarStoreId: {}, VarStoreInfo: 0x{:X}, MinSize: {}, MaxSize: {}, Flags: 0x{:X}", 
                                                strings_map.get(&st.PromptStringId).unwrap_or(&String::from("InvalidId")),
                                                strings_map.get(&st.HelpStringId).unwrap_or(&String::from("InvalidId")),
                                                st.QuestionFlags,
                                                st.QuestionId,
                                                st.VarStoreId,
                                                st.VarStoreInfo,
                                                st.MinSize,
                                                st.MaxSize,
                                                st.Flags).unwrap();
                                        }
                                        Err(e) => {
                                            write!(
                                                &mut text,
                                                "RawData: {:?}",
                                                operation.Data.unwrap()
                                            )
                                            .unwrap();
                                            println!("String parse error: {:?}", e);
                                        }
                                    }
                                }
                                // 0x1D: Refresh
                                parser::IfrOpcode::Refresh => {
                                    match parser::ifr_refresh(operation.Data.unwrap()) {
                                        Ok((_, refr)) => {
                                            write!(
                                                &mut text,
                                                "RefreshInterval: {}",
                                                refr.RefreshInterval
                                            )
                                            .unwrap();
                                        }
                                        Err(e) => {
                                            write!(
                                                &mut text,
                                                "RawData: {:?}",
                                                operation.Data.unwrap()
                                            )
                                            .unwrap();
                                            println!("Refresh parse error: {:?}", e);
                                        }
                                    }
                                }
                                // 0x1E: DisableIf
                                parser::IfrOpcode::DisableIf => {}
                                // 0x1F: Animation
                                parser::IfrOpcode::Animation => {
                                    match parser::ifr_animation(operation.Data.unwrap()) {
                                        Ok((_, anim)) => {
                                            write!(&mut text, "AnimationId: {}", anim.AnimationId)
                                                .unwrap();
                                        }
                                        Err(e) => {
                                            write!(
                                                &mut text,
                                                "RawData: {:?}",
                                                operation.Data.unwrap()
                                            )
                                            .unwrap();
                                            println!("Animation parse error: {:?}", e);
                                        }
                                    }
                                }
                                // 0x20: ToLower
                                parser::IfrOpcode::ToLower => {}
                                // 0x21: ToUpper
                                parser::IfrOpcode::ToUpper => {}
                                // 0x22: Map
                                parser::IfrOpcode::Map => {}
                                // 0x23: OrderedList
                                parser::IfrOpcode::OrderedList => {
                                    match parser::ifr_ordered_list(operation.Data.unwrap()) {
                                        Ok((_, ol)) => {
                                            write!(&mut text, "Prompt: \"{}\", Help: \"{}\", QuestionFlags: 0x{:X}, QuestionId: {}, VarStoreId: {}, VarStoreOffset: 0x{:X}, MaxContainers: {}, Flags: 0x{:X}", 
                                                strings_map.get(&ol.PromptStringId).unwrap_or(&String::from("InvalidId")),
                                                strings_map.get(&ol.HelpStringId).unwrap_or(&String::from("InvalidId")),
                                                ol.QuestionFlags,
                                                ol.QuestionId,
                                                ol.VarStoreId,
                                                ol.VarStoreInfo,
                                                ol.MaxContainers,
                                                ol.Flags).unwrap();
                                        }
                                        Err(e) => {
                                            write!(
                                                &mut text,
                                                "RawData: {:?}",
                                                operation.Data.unwrap()
                                            )
                                            .unwrap();
                                            println!("OrderedList parse error: {:?}", e);
                                        }
                                    }
                                }
                                // 0x24: VarStore
                                parser::IfrOpcode::VarStore => {
                                    match parser::ifr_var_store(operation.Data.unwrap()) {
                                        Ok((_, var_store)) => {
                                            write!(&mut text, "GUID: {}, VarStoreId: {}, Size: 0x{:X}, Name: \"{}\"", 
                                                var_store.Guid,
                                                var_store.VarStoreId,
                                                var_store.Size,
                                                var_store.Name).unwrap();
                                        }
                                        Err(e) => {
                                            write!(
                                                &mut text,
                                                "RawData: {:?}",
                                                operation.Data.unwrap()
                                            )
                                            .unwrap();
                                            println!("VarStore parse error: {:?}", e);
                                        }
                                    }
                                }
                                // 0x25: VarStoreNameValue
                                parser::IfrOpcode::VarStoreNameValue => {
                                    match parser::ifr_var_store_name_value(operation.Data.unwrap())
                                    {
                                        Ok((_, var_store)) => {
                                            write!(
                                                &mut text,
                                                "GUID: {}, VarStoreId: {}",
                                                var_store.Guid, var_store.VarStoreId
                                            )
                                            .unwrap();
                                        }
                                        Err(e) => {
                                            write!(
                                                &mut text,
                                                "RawData: {:?}",
                                                operation.Data.unwrap()
                                            )
                                            .unwrap();
                                            println!("VarStoreNameValue parse error: {:?}", e);
                                        }
                                    }
                                }
                                // 0x26: VarStoreEfi
                                parser::IfrOpcode::VarStoreEfi => {
                                    match parser::ifr_var_store_efi(operation.Data.unwrap()) {
                                        Ok((_, var_store)) => {
                                            write!(&mut text, "GUID: {}, VarStoreId: {}, Attributes: 0x{:X}, Size: 0x{:X}, Name: \"{}\"", 
                                                var_store.Guid,
                                                var_store.VarStoreId,
                                                var_store.Attributes,
                                                var_store.Size,
                                                var_store.Name).unwrap();
                                        }
                                        Err(e) => {
                                            write!(
                                                &mut text,
                                                "RawData: {:?}",
                                                operation.Data.unwrap()
                                            )
                                            .unwrap();
                                            println!("VarStoreEfi parse error: {:?}", e);
                                        }
                                    }
                                }
                                // 0x27: VarStoreDevice
                                parser::IfrOpcode::VarStoreDevice => {
                                    match parser::ifr_var_store_device(operation.Data.unwrap()) {
                                        Ok((_, var_store)) => {
                                            write!(
                                                &mut text,
                                                "DevicePath: \"{}\"",
                                                strings_map
                                                    .get(&var_store.DevicePathStringId)
                                                    .unwrap_or(&String::from("InvalidId"))
                                            )
                                            .unwrap();
                                        }
                                        Err(e) => {
                                            write!(
                                                &mut text,
                                                "RawData: {:?}",
                                                operation.Data.unwrap()
                                            )
                                            .unwrap();
                                            println!("VarStoreDevice parse error: {:?}", e);
                                        }
                                    }
                                }
                                // 0x28: Version
                                parser::IfrOpcode::Version => {}
                                // 0x29: End
                                parser::IfrOpcode::End => {}
                                // 0x2A: Match
                                parser::IfrOpcode::Match => {}
                                // 0x2B: Get
                                parser::IfrOpcode::Get => {
                                    match parser::ifr_get(operation.Data.unwrap()) {
                                        Ok((_, get)) => {
                                            write!(&mut text, "VarStoreId: {}, VarStoreInfo: {}, VarStoreType: {}", 
                                                get.VarStoreId,
                                                get.VarStoreInfo,
                                                get.VarStoreType).unwrap();
                                        }
                                        Err(e) => {
                                            write!(
                                                &mut text,
                                                "RawData: {:?}",
                                                operation.Data.unwrap()
                                            )
                                            .unwrap();
                                            println!("Get parse error: {:?}", e);
                                        }
                                    }
                                }
                                // 0x2C: Set
                                parser::IfrOpcode::Set => {
                                    match parser::ifr_set(operation.Data.unwrap()) {
                                        Ok((_, set)) => {
                                            write!(&mut text, "VarStoreId: {}, VarStoreInfo: {}, VarStoreType: {}", 
                                                set.VarStoreId,
                                                set.VarStoreInfo,
                                                set.VarStoreType).unwrap();
                                        }
                                        Err(e) => {
                                            write!(
                                                &mut text,
                                                "RawData: {:?}",
                                                operation.Data.unwrap()
                                            )
                                            .unwrap();
                                            println!("Set parse error: {:?}", e);
                                        }
                                    }
                                }
                                // 0x2D: Read
                                parser::IfrOpcode::Read => {}
                                // 0x2E: Write
                                parser::IfrOpcode::Write => {}
                                // 0x2F: Equal
                                parser::IfrOpcode::Equal => {}
                                // 0x30: NotEqual
                                parser::IfrOpcode::NotEqual => {}
                                // 0x31: GreaterThan
                                parser::IfrOpcode::GreaterThan => {}
                                // 0x32: GreaterEqual
                                parser::IfrOpcode::GreaterEqual => {}
                                // 0x33: LessThan
                                parser::IfrOpcode::LessThan => {}
                                // 0x34: LessEqual
                                parser::IfrOpcode::LessEqual => {}
                                // 0x35: BitwiseAnd
                                parser::IfrOpcode::BitwiseAnd => {}
                                // 0x36: BitwiseOr
                                parser::IfrOpcode::BitwiseOr => {}
                                // 0x37: BitwiseNot
                                parser::IfrOpcode::BitwiseNot => {}
                                // 0x38: ShiftLeft
                                parser::IfrOpcode::ShiftLeft => {}
                                // 0x39: ShiftRight
                                parser::IfrOpcode::ShiftRight => {}
                                // 0x3A: Add
                                parser::IfrOpcode::Add => {}
                                // 0x3B: Substract
                                parser::IfrOpcode::Substract => {}
                                // 0x3C: Multiply
                                parser::IfrOpcode::Multiply => {}
                                // 0x3D: Divide
                                parser::IfrOpcode::Divide => {}
                                // 0x3E: Modulo
                                parser::IfrOpcode::Modulo => {}
                                // 0x3F: RuleRef
                                parser::IfrOpcode::RuleRef => {
                                    match parser::ifr_rule_ref(operation.Data.unwrap()) {
                                        Ok((_, rule)) => {
                                            write!(&mut text, "RuleId: {}", rule.RuleId).unwrap();
                                        }
                                        Err(e) => {
                                            write!(
                                                &mut text,
                                                "RawData: {:?}",
                                                operation.Data.unwrap()
                                            )
                                            .unwrap();
                                            println!("RuleRef parse error: {:?}", e);
                                        }
                                    }
                                }
                                // 0x40: QuestionRef1
                                parser::IfrOpcode::QuestionRef1 => {
                                    match parser::ifr_question_ref_1(operation.Data.unwrap()) {
                                        Ok((_, qr)) => {
                                            write!(&mut text, "QuestionId: {}", qr.QuestionId)
                                                .unwrap();
                                        }
                                        Err(e) => {
                                            write!(
                                                &mut text,
                                                "RawData: {:?}",
                                                operation.Data.unwrap()
                                            )
                                            .unwrap();
                                            println!("QuestionRef1 parse error: {:?}", e);
                                        }
                                    }
                                }
                                // 0x41: QuestionRef2
                                parser::IfrOpcode::QuestionRef2 => {}
                                // 0x42: Uint8
                                parser::IfrOpcode::Uint8 => {
                                    match parser::ifr_uint8(operation.Data.unwrap()) {
                                        Ok((_, u)) => {
                                            write!(&mut text, "Value: {}", u.Value).unwrap();
                                        }
                                        Err(e) => {
                                            write!(
                                                &mut text,
                                                "RawData: {:?}",
                                                operation.Data.unwrap()
                                            )
                                            .unwrap();
                                            println!("Uint8 parse error: {:?}", e);
                                        }
                                    }
                                }
                                // 0x43: Uint16
                                parser::IfrOpcode::Uint16 => {
                                    match parser::ifr_uint16(operation.Data.unwrap()) {
                                        Ok((_, u)) => {
                                            write!(&mut text, "Value: {}", u.Value).unwrap();
                                        }
                                        Err(e) => {
                                            write!(
                                                &mut text,
                                                "RawData: {:?}",
                                                operation.Data.unwrap()
                                            )
                                            .unwrap();
                                            println!("Uint16 parse error: {:?}", e);
                                        }
                                    }
                                }
                                // 0x44: Uint32
                                parser::IfrOpcode::Uint32 => {
                                    match parser::ifr_uint32(operation.Data.unwrap()) {
                                        Ok((_, u)) => {
                                            write!(&mut text, "Value: {}", u.Value).unwrap();
                                        }
                                        Err(e) => {
                                            write!(
                                                &mut text,
                                                "RawData: {:?}",
                                                operation.Data.unwrap()
                                            )
                                            .unwrap();
                                            println!("Uint32 parse error: {:?}", e);
                                        }
                                    }
                                }
                                // 0x45: Uint64
                                parser::IfrOpcode::Uint64 => {
                                    match parser::ifr_uint64(operation.Data.unwrap()) {
                                        Ok((_, u)) => {
                                            write!(&mut text, "Value: {}", u.Value).unwrap();
                                        }
                                        Err(e) => {
                                            write!(
                                                &mut text,
                                                "RawData: {:?}",
                                                operation.Data.unwrap()
                                            )
                                            .unwrap();
                                            println!("Uint64 parse error: {:?}", e);
                                        }
                                    }
                                }
                                // 0x46: True
                                parser::IfrOpcode::True => {}
                                // 0x47: False
                                parser::IfrOpcode::False => {}
                                // 0x48: ToUint
                                parser::IfrOpcode::ToUint => {}
                                // 0x49: ToString
                                parser::IfrOpcode::ToString => {
                                    match parser::ifr_to_string(operation.Data.unwrap()) {
                                        Ok((_, ts)) => {
                                            write!(&mut text, "Format: 0x{:X}", ts.Format).unwrap();
                                        }
                                        Err(e) => {
                                            write!(
                                                &mut text,
                                                "RawData: {:?}",
                                                operation.Data.unwrap()
                                            )
                                            .unwrap();
                                            println!("ToString parse error: {:?}", e);
                                        }
                                    }
                                }
                                // 0x4A: ToBoolean
                                parser::IfrOpcode::ToBoolean => {}
                                // 0x4B: Mid
                                parser::IfrOpcode::Mid => {}
                                // 0x4C: Find
                                parser::IfrOpcode::Find => {
                                    match parser::ifr_find(operation.Data.unwrap()) {
                                        Ok((_, fnd)) => {
                                            write!(&mut text, "Format: 0x{:X}", fnd.Format)
                                                .unwrap();
                                        }
                                        Err(e) => {
                                            write!(
                                                &mut text,
                                                "RawData: {:?}",
                                                operation.Data.unwrap()
                                            )
                                            .unwrap();
                                            println!("Find parse error: {:?}", e);
                                        }
                                    }
                                }
                                // 0x4D: Token
                                parser::IfrOpcode::Token => {}
                                // 0x4E: StringRef1
                                parser::IfrOpcode::StringRef1 => {
                                    match parser::ifr_string_ref_1(operation.Data.unwrap()) {
                                        Ok((_, st)) => {
                                            write!(
                                                &mut text,
                                                "String: \"{}\"",
                                                strings_map
                                                    .get(&st.StringId)
                                                    .unwrap_or(&String::from("InvalidId"))
                                            )
                                            .unwrap();
                                        }
                                        Err(e) => {
                                            write!(
                                                &mut text,
                                                "RawData: {:?}",
                                                operation.Data.unwrap()
                                            )
                                            .unwrap();
                                            println!("StringRef1 parse error: {:?}", e);
                                        }
                                    }
                                }
                                // 0x4F: StringRef2
                                parser::IfrOpcode::StringRef2 => {}
                                // 0x50: Conditional
                                parser::IfrOpcode::Conditional => {}
                                // 0x51: QuestionRef3
                                parser::IfrOpcode::QuestionRef3 => {
                                    if let Some(_) = operation.Data {
                                        match parser::ifr_question_ref_3(operation.Data.unwrap()) {
                                            Ok((_, qr)) => {
                                                if let Some(x) = qr.DevicePathId {
                                                    write!(
                                                        &mut text,
                                                        "DevicePath: \"{}\"",
                                                        strings_map
                                                            .get(&x)
                                                            .unwrap_or(&String::from("InvalidId"))
                                                    )
                                                    .unwrap();
                                                }
                                                if let Some(x) = qr.QuestionGuid {
                                                    write!(&mut text, "Guid: {}", x).unwrap();
                                                }
                                            }
                                            Err(e) => {
                                                write!(
                                                    &mut text,
                                                    "RawData: {:?}",
                                                    operation.Data.unwrap()
                                                )
                                                .unwrap();
                                                println!("QuestionRef3 parse error: {:?}", e);
                                            }
                                        }
                                    }
                                }
                                // 0x52: Zero
                                parser::IfrOpcode::Zero => {}
                                // 0x53: One
                                parser::IfrOpcode::One => {}
                                // 0x54: Ones
                                parser::IfrOpcode::Ones => {}
                                // 0x55: Undefined
                                parser::IfrOpcode::Undefined => {}
                                // 0x56: Length
                                parser::IfrOpcode::Length => {}
                                // 0x57: Dup
                                parser::IfrOpcode::Dup => {}
                                // 0x58: This
                                parser::IfrOpcode::This => {}
                                // 0x59: Span
                                parser::IfrOpcode::Span => {
                                    match parser::ifr_span(operation.Data.unwrap()) {
                                        Ok((_, span)) => {
                                            write!(&mut text, "Flags: 0x{:X}", span.Flags).unwrap();
                                        }
                                        Err(e) => {
                                            write!(
                                                &mut text,
                                                "RawData: {:?}",
                                                operation.Data.unwrap()
                                            )
                                            .unwrap();
                                            println!("Span parse error: {:?}", e);
                                        }
                                    }
                                }
                                // 0x5A: Value
                                parser::IfrOpcode::Value => {}
                                // 0x5B: Default
                                parser::IfrOpcode::Default => {
                                    match parser::ifr_default(operation.Data.unwrap()) {
                                        Ok((_, def)) => {
                                            write!(&mut text, "DefaultId: {} ", def.DefaultId)
                                                .unwrap();
                                            match def.Value {
                                                parser::IfrTypeValue::String(x) => {
                                                    write!(
                                                        &mut text,
                                                        "String: \"{}\"",
                                                        strings_map
                                                            .get(&x)
                                                            .unwrap_or(&String::from("InvalidId"))
                                                    )
                                                    .unwrap();
                                                }
                                                parser::IfrTypeValue::Action(x) => {
                                                    write!(
                                                        &mut text,
                                                        "Action: \"{}\"",
                                                        strings_map
                                                            .get(&x)
                                                            .unwrap_or(&String::from("InvalidId"))
                                                    )
                                                    .unwrap();
                                                }
                                                _ => {
                                                    write!(&mut text, "Value: {}", def.Value)
                                                        .unwrap();
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            write!(
                                                &mut text,
                                                "RawData: {:?}",
                                                operation.Data.unwrap()
                                            )
                                            .unwrap();
                                            println!("Default parse error: {:?}", e);
                                        }
                                    }
                                }
                                // 0x5C: DefaultStore
                                parser::IfrOpcode::DefaultStore => {
                                    match parser::ifr_default_store(operation.Data.unwrap()) {
                                        Ok((_, default_store)) => {
                                            write!(
                                                &mut text,
                                                "DefaultId: {}, Name: \"{}\"",
                                                default_store.DefaultId,
                                                strings_map
                                                    .get(&default_store.NameStringId)
                                                    .unwrap_or(&String::from("InvalidId"))
                                            )
                                            .unwrap();
                                        }
                                        Err(e) => {
                                            write!(
                                                &mut text,
                                                "RawData: {:?}",
                                                operation.Data.unwrap()
                                            )
                                            .unwrap();
                                            println!("DefaultStore parse error: {:?}", e);
                                        }
                                    }
                                }
                                // 0x5D: FormMap
                                parser::IfrOpcode::FormMap => {
                                    match parser::ifr_form_map(operation.Data.unwrap()) {
                                        Ok((_, form_map)) => {
                                            write!(&mut text, "FormId: {}", form_map.FormId)
                                                .unwrap();
                                            for method in form_map.Methods {
                                                write!(
                                                    &mut text,
                                                    "| GUID: {}, Method: \"{}\"",
                                                    method.MethodIdentifier,
                                                    strings_map
                                                        .get(&method.MethodTitleId)
                                                        .unwrap_or(&String::from("InvalidId"))
                                                )
                                                .unwrap();
                                            }
                                        }
                                        Err(e) => {
                                            write!(
                                                &mut text,
                                                "RawData: {:?}",
                                                operation.Data.unwrap()
                                            )
                                            .unwrap();
                                            println!("FormMap parse error: {:?}", e);
                                        }
                                    }
                                }
                                // 0x5E: Catenate
                                parser::IfrOpcode::Catenate => {}
                                // 0x5F: GUID
                                parser::IfrOpcode::Guid => {
                                    match parser::ifr_guid(operation.Data.unwrap()) {
                                        Ok((_, guid)) => {
                                            // This manual parsing here is ugly and can ultimately be done using nom,
                                            // but it's done already and not that important anyway
                                            // TODO: refactor later
                                            let mut done = false;
                                            match guid.Guid {
                                                parser::IFR_TIANO_GUID => {
                                                    if let Ok((_, edk2)) =
                                                        parser::ifr_guid_edk2(guid.Data)
                                                    {
                                                        match edk2.ExtendedOpCode {
                                                            parser::IfrEdk2ExtendOpCode::Banner => {
                                                                if let Ok((_, banner)) = parser::ifr_guid_edk2_banner(edk2.Data) {
                                                                    write!(&mut text, "Guid: {}, ExtendedOpCode: {:?}, Title: \"{}\", LineNumber: {}, Alignment: {} ", 
                                                                    guid.Guid,
                                                                    edk2.ExtendedOpCode,
                                                                    strings_map.get(&banner.TitleId).unwrap_or(&String::from("InvalidId")),
                                                                    banner.LineNumber,
                                                                    banner.Alignment).unwrap();
                                                                    done = true;
                                                                }
                                                            }
                                                            parser::IfrEdk2ExtendOpCode::Label => {
                                                                if edk2.Data.len() == 2 {
                                                                    write!(&mut text, "Guid: {}, ExtendedOpCode: {:?}, LabelNumber: {}", 
                                                                        guid.Guid,
                                                                        edk2.ExtendedOpCode,
                                                                        edk2.Data[1] as u16 * 100 + edk2.Data[0] as u16).unwrap();
                                                                    done = true;
                                                                }
                                                            }
                                                            parser::IfrEdk2ExtendOpCode::Timeout => {
                                                                if edk2.Data.len() == 2 {
                                                                    write!(&mut text, "Guid: {}, ExtendedOpCode: {:?}, Timeout: {}", 
                                                                        guid.Guid,
                                                                        edk2.ExtendedOpCode,
                                                                        edk2.Data[1] as u16 * 100 + edk2.Data[0] as u16).unwrap();
                                                                    done = true;
                                                                }
                                                            }
                                                            parser::IfrEdk2ExtendOpCode::Class => {
                                                                if edk2.Data.len() == 2 {
                                                                    write!(&mut text, "Guid: {}, ExtendedOpCode: {:?}, Class: {}", 
                                                                        guid.Guid,
                                                                        edk2.ExtendedOpCode,
                                                                        edk2.Data[1] as u16 * 100 + edk2.Data[0] as u16).unwrap();
                                                                    done = true;
                                                                }
                                                            }
                                                            parser::IfrEdk2ExtendOpCode::SubClass => {
                                                                if edk2.Data.len() == 2 {
                                                                    write!(&mut text, "Guid: {}, ExtendedOpCode: {:?}, SubClass: {}", 
                                                                        guid.Guid,
                                                                        edk2.ExtendedOpCode,
                                                                        edk2.Data[1] as u16 * 100 + edk2.Data[0] as u16).unwrap();
                                                                    done = true;
                                                                }
                                                            }
                                                            parser::IfrEdk2ExtendOpCode::Unknown(_) => {}
                                                        }
                                                    }
                                                }
                                                parser::IFR_FRAMEWORK_GUID => {
                                                    if let Ok((_, edk)) =
                                                        parser::ifr_guid_edk(guid.Data)
                                                    {
                                                        match edk.ExtendedOpCode {
                                                            parser::IfrEdkExtendOpCode::OptionKey => {
                                                                write!(&mut text, "Guid: {}, ExtendedOpCode: {:?}, QuestionId: {}, Data: {:?}", 
                                                                        guid.Guid,
                                                                        edk.ExtendedOpCode,
                                                                        edk.QuestionId,
                                                                        edk.Data).unwrap();
                                                                done = true;
                                                            }
                                                            parser::IfrEdkExtendOpCode::VarEqName => {
                                                                if edk.Data.len() == 2 {
                                                                    let name_id = edk.Data[1] as u16 * 100 + edk.Data[0] as u16;
                                                                    write!(&mut text, "Guid: {}, ExtendedOpCode: {:?}, QuestionId: {}, Name: \"{}\"", 
                                                                        guid.Guid,
                                                                        edk.ExtendedOpCode,
                                                                        edk.QuestionId,
                                                                        strings_map.get(&name_id).unwrap_or(&String::from("InvalidId"))).unwrap();
                                                                    done = true;
                                                                }
                                                            }
                                                            parser::IfrEdkExtendOpCode::Unknown(_) => {}
                                                        }
                                                    }
                                                }
                                                _ => {}
                                            }
                                            if !done {
                                                write!(
                                                    &mut text,
                                                    "Guid: {}, Optional data: {:?}",
                                                    guid.Guid, guid.Data
                                                )
                                                .unwrap();
                                            }
                                        }
                                        Err(e) => {
                                            write!(
                                                &mut text,
                                                "RawData: {:?}",
                                                operation.Data.unwrap()
                                            )
                                            .unwrap();
                                            println!("Guid parse error: {:?}", e);
                                        }
                                    }
                                }
                                // 0x60: Security
                                parser::IfrOpcode::Security => {
                                    match parser::ifr_security(operation.Data.unwrap()) {
                                        Ok((_, sec)) => {
                                            write!(&mut text, "Guid: {}", sec.Guid).unwrap();
                                        }
                                        Err(e) => {
                                            write!(
                                                &mut text,
                                                "RawData: {:?}",
                                                operation.Data.unwrap()
                                            )
                                            .unwrap();
                                            println!("Security parse error: {:?}", e);
                                        }
                                    }
                                }
                                // 0x61: ModalTag
                                parser::IfrOpcode::ModalTag => {}
                                // 0x62: RefreshId
                                parser::IfrOpcode::RefreshId => {
                                    match parser::ifr_refresh_id(operation.Data.unwrap()) {
                                        Ok((_, rid)) => {
                                            write!(&mut text, "Guid: {}", rid.Guid).unwrap();
                                        }
                                        Err(e) => {
                                            write!(
                                                &mut text,
                                                "RawData: {:?}",
                                                operation.Data.unwrap()
                                            )
                                            .unwrap();
                                            println!("RefreshId parse error: {:?}", e);
                                        }
                                    }
                                }
                                // 0x63: WarningIf
                                parser::IfrOpcode::WarningIf => {
                                    match parser::ifr_warning_if(operation.Data.unwrap()) {
                                        Ok((_, warn)) => {
                                            write!(
                                                &mut text,
                                                "Timeout: {}, Warning: \"{}\"",
                                                warn.Timeout,
                                                strings_map
                                                    .get(&warn.WarningStringId)
                                                    .unwrap_or(&String::from("InvalidId"))
                                            )
                                            .unwrap();
                                        }
                                        Err(e) => {
                                            write!(
                                                &mut text,
                                                "RawData: {:?}",
                                                operation.Data.unwrap()
                                            )
                                            .unwrap();
                                            println!("WarningIf parse error: {:?}", e);
                                        }
                                    }
                                }
                                // 0x64: Match2
                                parser::IfrOpcode::Match2 => {
                                    match parser::ifr_match_2(operation.Data.unwrap()) {
                                        Ok((_, m2)) => {
                                            write!(&mut text, "Guid: {}", m2.Guid).unwrap();
                                        }
                                        Err(e) => {
                                            write!(
                                                &mut text,
                                                "RawData: {:?}",
                                                operation.Data.unwrap()
                                            )
                                            .unwrap();
                                            println!("Match2 parse error: {:?}", e);
                                        }
                                    }
                                }
                                // Unknown operation
                                parser::IfrOpcode::Unknown(x) => {
                                    write!(&mut text, "RawData: {:?}", operation.Data.unwrap())
                                        .unwrap();
                                    println!("IFR operation of unknown type 0x{:X}", x);
                                }
                            }
                            writeln!(&mut text, "").unwrap();

                            if operation.ScopeStart == true {
                                scope_depth += 1;
                            }
                        }
                    }
                    Err(e) => {
                        println!("IFR operations parse error: {:?}", e);
                    }
                }
            } else {
                i += 1;
            }
        } else {
            i += 1;
        }
    }

    // Write the result
    let mut file_path = OsString::new();
    file_path.push(path);
    file_path.push(".ifr.txt");
    let mut output_file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .create(true)
        .open(&file_path)
        .expect(&format!("Can't create output file {:?}", &file_path));
    output_file
        .write(&text)
        .expect(&format!("Can't write to output file {:?}", file_path));
}
