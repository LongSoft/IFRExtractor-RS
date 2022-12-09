// Parser
#[macro_use]
extern crate nom;
pub mod framework_parser;
pub mod uefi_parser;

// Main
use std::collections::HashMap;
use std::env;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::prelude::*;
use std::io::Write;
use std::path::Path;
use std::str;

struct StringPackage {
    offset: usize,
    length: usize,
    language: String,
    string_id_map: HashMap<u16, String>,
}

struct FormPackage {
    offset: usize,
    length: usize,
    used_strings: usize,
    min_string_id: u16,
    max_string_id: u16,
}

const VERSION: Option<&'static str> = option_env!("CARGO_PKG_VERSION");

//
// UEFI HII parsing
//
fn uefi_find_string_and_form_packages(data: &[u8]) -> (Vec<StringPackage>, Vec<FormPackage>) {
    let mut strings = Vec::new(); // String-to-id maps for all found string packages

    // Search for all string packages in the input file
    let mut i = 0;
    while i < data.len() {
        if let Ok((_, candidate)) = uefi_parser::hii_string_package_candidate(&data[i..]) {
            if let Ok((_, package)) = uefi_parser::hii_package(candidate) {
                if let Ok((_, string_package)) =
                    uefi_parser::hii_string_package(package.Data.unwrap())
                {
                    let mut string_id_map = HashMap::new(); // Map of StringIds to strings

                    // Parse SIBT blocks
                    if let Ok((_, sibt_blocks)) = uefi_parser::hii_sibt_blocks(string_package.Data)
                    {
                        string_id_map.insert(0 as u16, String::new());
                        let mut current_string_index = 1;
                        for block in &sibt_blocks {
                            match block.Type {
                                // 0x00: End
                                uefi_parser::HiiSibtType::End => {}
                                // 0x10: StringScsu
                                uefi_parser::HiiSibtType::StringScsu => {
                                    if let Ok((_, string)) =
                                        uefi_parser::sibt_string_scsu(block.Data.unwrap())
                                    {
                                        string_id_map.insert(current_string_index, string);
                                        current_string_index += 1;
                                    }
                                }
                                // 0x11: StringScsuFont
                                uefi_parser::HiiSibtType::StringScsuFont => {
                                    if let Ok((_, string)) =
                                        uefi_parser::sibt_string_scsu_font(block.Data.unwrap())
                                    {
                                        string_id_map.insert(current_string_index, string);
                                        current_string_index += 1;
                                    }
                                }
                                // 0x12: StringsScsu
                                uefi_parser::HiiSibtType::StringsScsu => {
                                    if let Ok((_, strings)) =
                                        uefi_parser::sibt_strings_scsu(block.Data.unwrap())
                                    {
                                        for string in strings {
                                            string_id_map.insert(current_string_index, string);
                                            current_string_index += 1;
                                        }
                                    }
                                }
                                // 0x13: StringsScsuFont
                                uefi_parser::HiiSibtType::StringsScsuFont => {
                                    if let Ok((_, strings)) =
                                        uefi_parser::sibt_strings_scsu_font(block.Data.unwrap())
                                    {
                                        for string in strings {
                                            string_id_map.insert(current_string_index, string);
                                            current_string_index += 1;
                                        }
                                    }
                                }
                                // 0x14: StringUcs2
                                uefi_parser::HiiSibtType::StringUcs2 => {
                                    if let Ok((_, string)) =
                                        uefi_parser::sibt_string_ucs2(block.Data.unwrap())
                                    {
                                        string_id_map.insert(current_string_index, string);
                                        current_string_index += 1;
                                    }
                                }
                                // 0x15: StringUcs2Font
                                uefi_parser::HiiSibtType::StringUcs2Font => {
                                    if let Ok((_, string)) =
                                        uefi_parser::sibt_string_ucs2_font(block.Data.unwrap())
                                    {
                                        string_id_map.insert(current_string_index, string);
                                        current_string_index += 1;
                                    }
                                }
                                // 0x16: StringsUcs2
                                uefi_parser::HiiSibtType::StringsUcs2 => {
                                    if let Ok((_, strings)) =
                                        uefi_parser::sibt_strings_ucs2(block.Data.unwrap())
                                    {
                                        for string in strings {
                                            string_id_map.insert(current_string_index, string);
                                            current_string_index += 1;
                                        }
                                    }
                                }
                                // 0x17: StringsUcs2Font
                                uefi_parser::HiiSibtType::StringsUcs2Font => {
                                    if let Ok((_, strings)) =
                                        uefi_parser::sibt_strings_ucs2_font(block.Data.unwrap())
                                    {
                                        for string in strings {
                                            string_id_map.insert(current_string_index, string);
                                            current_string_index += 1;
                                        }
                                    }
                                }
                                // 0x20: Duplicate
                                uefi_parser::HiiSibtType::Duplicate => {
                                    current_string_index += 1;
                                }
                                // 0x21: Skip2
                                uefi_parser::HiiSibtType::Skip2 => {
                                    // Manual parsing of Data as u16
                                    let count = block.Data.unwrap();
                                    current_string_index +=
                                        count[0] as u16 + 0x100 * count[1] as u16;
                                }
                                // 0x22: Skip1
                                uefi_parser::HiiSibtType::Skip1 => {
                                    // Manual parsing of Data as u8
                                    let count = block.Data.unwrap();
                                    current_string_index += count[0] as u16;
                                }
                                // Blocks below don't have any strings nor can they influence current_string_index
                                // No need to parse them here
                                // 0x30: Ext1
                                uefi_parser::HiiSibtType::Ext1 => {}
                                // 0x31: Ext2
                                uefi_parser::HiiSibtType::Ext2 => {}
                                // 0x32: Ext4
                                uefi_parser::HiiSibtType::Ext4 => {}
                                // Unknown SIBT block is impossible, because parsing will fail on it due to it's unknown length
                                uefi_parser::HiiSibtType::Unknown(_) => {}
                            }
                        }

                        // Add string
                        let string = (i, candidate.len(), string_package.Language, string_id_map);
                        strings.push(string);
                    }

                    i += candidate.len();
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

    // No need to continue if there are no string packages found
    if strings.len() == 0 {
        return (Vec::new(), Vec::new());
    }

    //
    // Search for all form packages in the input file
    //
    let mut forms = Vec::new();
    i = 0;
    while i < data.len() {
        if let Ok((_, candidate)) = uefi_parser::hii_form_package_candidate(&data[i..]) {
            if let Ok((_, package)) = uefi_parser::hii_package(candidate) {
                // Parse form package and obtain StringIds
                let mut string_ids: Vec<u16> = Vec::new();
                if let Ok((_, operations)) = uefi_parser::ifr_operations(package.Data.unwrap()) {
                    //let mut current_operation: usize = 0;
                    for operation in &operations {
                        //current_operation += 1;
                        //println!("Operation #{}, OpCode: {:?}, Length 0x{:X}, ScopeStart: {}", current_operation, operation.OpCode, operation.Length, operation.ScopeStart);
                        match operation.OpCode {
                            // 0x01: Form
                            uefi_parser::IfrOpcode::Form => {
                                if let Ok((_, form)) =
                                    uefi_parser::ifr_form(operation.Data.unwrap())
                                {
                                    string_ids.push(form.TitleStringId);
                                }
                            }
                            // 0x02: Subtitle
                            uefi_parser::IfrOpcode::Subtitle => {
                                if let Ok((_, sub)) =
                                    uefi_parser::ifr_subtitle(operation.Data.unwrap())
                                {
                                    string_ids.push(sub.PromptStringId);
                                    string_ids.push(sub.HelpStringId);
                                }
                            }
                            // 0x03: Text
                            uefi_parser::IfrOpcode::Text => {
                                if let Ok((_, txt)) = uefi_parser::ifr_text(operation.Data.unwrap())
                                {
                                    string_ids.push(txt.PromptStringId);
                                    string_ids.push(txt.HelpStringId);
                                    string_ids.push(txt.TextId);
                                }
                            }
                            // 0x04: Image
                            uefi_parser::IfrOpcode::Image => {}
                            // 0x05: OneOf
                            uefi_parser::IfrOpcode::OneOf => {
                                if let Ok((_, onf)) =
                                    uefi_parser::ifr_one_of(operation.Data.unwrap())
                                {
                                    string_ids.push(onf.PromptStringId);
                                    string_ids.push(onf.HelpStringId);
                                }
                            }
                            // 0x06: CheckBox
                            uefi_parser::IfrOpcode::CheckBox => {
                                if let Ok((_, cb)) =
                                    uefi_parser::ifr_check_box(operation.Data.unwrap())
                                {
                                    string_ids.push(cb.PromptStringId);
                                    string_ids.push(cb.HelpStringId);
                                }
                            }
                            // 0x07: Numeric
                            uefi_parser::IfrOpcode::Numeric => {
                                if let Ok((_, num)) =
                                    uefi_parser::ifr_numeric(operation.Data.unwrap())
                                {
                                    string_ids.push(num.PromptStringId);
                                    string_ids.push(num.HelpStringId);
                                }
                            }
                            // 0x08: Password
                            uefi_parser::IfrOpcode::Password => {
                                if let Ok((_, pw)) =
                                    uefi_parser::ifr_password(operation.Data.unwrap())
                                {
                                    string_ids.push(pw.PromptStringId);
                                    string_ids.push(pw.HelpStringId);
                                }
                            }
                            // 0x09: OneOfOption
                            uefi_parser::IfrOpcode::OneOfOption => {
                                if let Ok((_, opt)) =
                                    uefi_parser::ifr_one_of_option(operation.Data.unwrap())
                                {
                                    string_ids.push(opt.OptionStringId);
                                    match opt.Value {
                                        uefi_parser::IfrTypeValue::String(x) => {
                                            string_ids.push(x);
                                        }
                                        uefi_parser::IfrTypeValue::Action(x) => {
                                            string_ids.push(x);
                                        }
                                        _ => {}
                                    }
                                }
                            }
                            // 0x0A: SuppressIf
                            uefi_parser::IfrOpcode::SuppressIf => {}
                            // 0x0B: Locked
                            uefi_parser::IfrOpcode::Locked => {}
                            // 0x0C: Action
                            uefi_parser::IfrOpcode::Action => {
                                if let Ok((_, act)) =
                                    uefi_parser::ifr_action(operation.Data.unwrap())
                                {
                                    string_ids.push(act.PromptStringId);
                                    string_ids.push(act.HelpStringId);
                                    if let Some(x) = act.ConfigStringId {
                                        string_ids.push(x);
                                    }
                                }
                            }
                            // 0x0D: ResetButton
                            uefi_parser::IfrOpcode::ResetButton => {
                                if let Ok((_, rst)) =
                                    uefi_parser::ifr_reset_button(operation.Data.unwrap())
                                {
                                    string_ids.push(rst.PromptStringId);
                                    string_ids.push(rst.HelpStringId);
                                }
                            }
                            // 0x0E: FormSet
                            uefi_parser::IfrOpcode::FormSet => {
                                if let Ok((_, form_set)) =
                                    uefi_parser::ifr_form_set(operation.Data.unwrap())
                                {
                                    string_ids.push(form_set.TitleStringId);
                                    string_ids.push(form_set.HelpStringId);
                                }
                            }
                            // 0x0F: Ref
                            uefi_parser::IfrOpcode::Ref => {
                                if let Ok((_, rf)) = uefi_parser::ifr_ref(operation.Data.unwrap()) {
                                    string_ids.push(rf.PromptStringId);
                                    string_ids.push(rf.HelpStringId);
                                }
                            }
                            // 0x10: NoSubmitIf
                            uefi_parser::IfrOpcode::NoSubmitIf => {
                                if let Ok((_, ns)) =
                                    uefi_parser::ifr_no_submit_if(operation.Data.unwrap())
                                {
                                    string_ids.push(ns.ErrorStringId);
                                }
                            }
                            // 0x11: InconsistentIf
                            uefi_parser::IfrOpcode::InconsistentIf => {
                                if let Ok((_, inc)) =
                                    uefi_parser::ifr_inconsistent_if(operation.Data.unwrap())
                                {
                                    string_ids.push(inc.ErrorStringId);
                                }
                            }
                            // 0x12: EqIdVal
                            uefi_parser::IfrOpcode::EqIdVal => {}
                            // 0x13: EqIdId
                            uefi_parser::IfrOpcode::EqIdId => {}
                            // 0x14: EqIdValList
                            uefi_parser::IfrOpcode::EqIdValList => {}
                            // 0x15: And
                            uefi_parser::IfrOpcode::And => {}
                            // 0x16: Or
                            uefi_parser::IfrOpcode::Or => {}
                            // 0x17: Not
                            uefi_parser::IfrOpcode::Not => {}
                            // 0x18: Rule
                            uefi_parser::IfrOpcode::Rule => {}
                            // 0x19: GrayOutIf
                            uefi_parser::IfrOpcode::GrayOutIf => {}
                            // 0x1A: Date
                            uefi_parser::IfrOpcode::Date => {
                                if let Ok((_, dt)) = uefi_parser::ifr_date(operation.Data.unwrap())
                                {
                                    string_ids.push(dt.PromptStringId);
                                    string_ids.push(dt.HelpStringId);
                                }
                            }
                            // 0x1B: Time
                            uefi_parser::IfrOpcode::Time => {
                                if let Ok((_, time)) =
                                    uefi_parser::ifr_time(operation.Data.unwrap())
                                {
                                    string_ids.push(time.PromptStringId);
                                    string_ids.push(time.HelpStringId);
                                }
                            }
                            // 0x1C: String
                            uefi_parser::IfrOpcode::String => {
                                if let Ok((_, st)) =
                                    uefi_parser::ifr_string(operation.Data.unwrap())
                                {
                                    string_ids.push(st.PromptStringId);
                                    string_ids.push(st.HelpStringId);
                                }
                            }
                            // 0x1D: Refresh
                            uefi_parser::IfrOpcode::Refresh => {}
                            // 0x1E: DisableIf
                            uefi_parser::IfrOpcode::DisableIf => {}
                            // 0x1F: Animation
                            uefi_parser::IfrOpcode::Animation => {}
                            // 0x20: ToLower
                            uefi_parser::IfrOpcode::ToLower => {}
                            // 0x21: ToUpper
                            uefi_parser::IfrOpcode::ToUpper => {}
                            // 0x22: Map
                            uefi_parser::IfrOpcode::Map => {}
                            // 0x23: OrderedList
                            uefi_parser::IfrOpcode::OrderedList => {
                                if let Ok((_, ol)) =
                                    uefi_parser::ifr_ordered_list(operation.Data.unwrap())
                                {
                                    string_ids.push(ol.PromptStringId);
                                    string_ids.push(ol.HelpStringId);
                                }
                            }
                            // 0x24: VarStore
                            uefi_parser::IfrOpcode::VarStore => {}
                            // 0x25: VarStoreNameValue
                            uefi_parser::IfrOpcode::VarStoreNameValue => {}
                            // 0x26: VarStoreEfi258
                            uefi_parser::IfrOpcode::VarStoreEfi => {}
                            // 0x27: VarStoreDevice
                            uefi_parser::IfrOpcode::VarStoreDevice => {
                                if let Ok((_, var_store)) =
                                    uefi_parser::ifr_var_store_device(operation.Data.unwrap())
                                {
                                    string_ids.push(var_store.DevicePathStringId);
                                }
                            }
                            // 0x28: Version
                            uefi_parser::IfrOpcode::Version => {}
                            // 0x29: End
                            uefi_parser::IfrOpcode::End => {}
                            // 0x2A: Match
                            uefi_parser::IfrOpcode::Match => {}
                            // 0x2B: Get
                            uefi_parser::IfrOpcode::Get => {}
                            // 0x2C: Set
                            uefi_parser::IfrOpcode::Set => {}
                            // 0x2D: Read
                            uefi_parser::IfrOpcode::Read => {}
                            // 0x2E: Write
                            uefi_parser::IfrOpcode::Write => {}
                            // 0x2F: Equal
                            uefi_parser::IfrOpcode::Equal => {}
                            // 0x30: NotEqual
                            uefi_parser::IfrOpcode::NotEqual => {}
                            // 0x31: GreaterThan
                            uefi_parser::IfrOpcode::GreaterThan => {}
                            // 0x32: GreaterEqual
                            uefi_parser::IfrOpcode::GreaterEqual => {}
                            // 0x33: LessThan
                            uefi_parser::IfrOpcode::LessThan => {}
                            // 0x34: LessEqual
                            uefi_parser::IfrOpcode::LessEqual => {}
                            // 0x35: BitwiseAnd
                            uefi_parser::IfrOpcode::BitwiseAnd => {}
                            // 0x36: BitwiseOr
                            uefi_parser::IfrOpcode::BitwiseOr => {}
                            // 0x37: BitwiseNot
                            uefi_parser::IfrOpcode::BitwiseNot => {}
                            // 0x38: ShiftLeft
                            uefi_parser::IfrOpcode::ShiftLeft => {}
                            // 0x39: ShiftRight
                            uefi_parser::IfrOpcode::ShiftRight => {}
                            // 0x3A: Add
                            uefi_parser::IfrOpcode::Add => {}
                            // 0x3B: Substract
                            uefi_parser::IfrOpcode::Substract => {}
                            // 0x3C: Multiply
                            uefi_parser::IfrOpcode::Multiply => {}
                            // 0x3D: Divide
                            uefi_parser::IfrOpcode::Divide => {}
                            // 0x3E: Modulo
                            uefi_parser::IfrOpcode::Modulo => {}
                            // 0x3F: RuleRef
                            uefi_parser::IfrOpcode::RuleRef => {}
                            // 0x40: QuestionRef1
                            uefi_parser::IfrOpcode::QuestionRef1 => {}
                            // 0x41: QuestionRef2
                            uefi_parser::IfrOpcode::QuestionRef2 => {}
                            // 0x42: Uint8
                            uefi_parser::IfrOpcode::Uint8 => {}
                            // 0x43: Uint16
                            uefi_parser::IfrOpcode::Uint16 => {}
                            // 0x44: Uint32
                            uefi_parser::IfrOpcode::Uint32 => {}
                            // 0x45: Uint64
                            uefi_parser::IfrOpcode::Uint64 => {}
                            // 0x46: True
                            uefi_parser::IfrOpcode::True => {}
                            // 0x47: False
                            uefi_parser::IfrOpcode::False => {}
                            // 0x48: ToUint
                            uefi_parser::IfrOpcode::ToUint => {}
                            // 0x49: ToString
                            uefi_parser::IfrOpcode::ToString => {}
                            // 0x4A: ToBoolean
                            uefi_parser::IfrOpcode::ToBoolean => {}
                            // 0x4B: Mid
                            uefi_parser::IfrOpcode::Mid => {}
                            // 0x4C: Find
                            uefi_parser::IfrOpcode::Find => {}
                            // 0x4D: Token
                            uefi_parser::IfrOpcode::Token => {}
                            // 0x4E: StringRef1
                            uefi_parser::IfrOpcode::StringRef1 => {
                                if let Ok((_, st)) =
                                    uefi_parser::ifr_string_ref_1(operation.Data.unwrap())
                                {
                                    string_ids.push(st.StringId);
                                }
                            }
                            // 0x4F: StringRef2
                            uefi_parser::IfrOpcode::StringRef2 => {}
                            // 0x50: Conditional
                            uefi_parser::IfrOpcode::Conditional => {}
                            // 0x51: QuestionRef3
                            uefi_parser::IfrOpcode::QuestionRef3 => {
                                if let Some(_) = operation.Data {
                                    if let Ok((_, qr)) =
                                        uefi_parser::ifr_question_ref_3(operation.Data.unwrap())
                                    {
                                        if let Some(x) = qr.DevicePathId {
                                            string_ids.push(x);
                                        }
                                    }
                                }
                            }
                            // 0x52: Zero
                            uefi_parser::IfrOpcode::Zero => {}
                            // 0x53: One
                            uefi_parser::IfrOpcode::One => {}
                            // 0x54: Ones
                            uefi_parser::IfrOpcode::Ones => {}
                            // 0x55: Undefined
                            uefi_parser::IfrOpcode::Undefined => {}
                            // 0x56: Length
                            uefi_parser::IfrOpcode::Length => {}
                            // 0x57: Dup
                            uefi_parser::IfrOpcode::Dup => {}
                            // 0x58: This
                            uefi_parser::IfrOpcode::This => {}
                            // 0x59: Span
                            uefi_parser::IfrOpcode::Span => {}
                            // 0x5A: Value
                            uefi_parser::IfrOpcode::Value => {}
                            // 0x5B: Default
                            uefi_parser::IfrOpcode::Default => {
                                if let Ok((_, def)) =
                                    uefi_parser::ifr_default(operation.Data.unwrap())
                                {
                                    match def.Value {
                                        uefi_parser::IfrTypeValue::String(x) => {
                                            string_ids.push(x);
                                        }
                                        uefi_parser::IfrTypeValue::Action(x) => {
                                            string_ids.push(x);
                                        }
                                        _ => {}
                                    }
                                }
                            }
                            // 0x5C: DefaultStore
                            uefi_parser::IfrOpcode::DefaultStore => {
                                if let Ok((_, default_store)) =
                                    uefi_parser::ifr_default_store(operation.Data.unwrap())
                                {
                                    string_ids.push(default_store.NameStringId);
                                }
                            }
                            // 0x5D: FormMap
                            uefi_parser::IfrOpcode::FormMap => {
                                if let Ok((_, form_map)) =
                                    uefi_parser::ifr_form_map(operation.Data.unwrap())
                                {
                                    for method in form_map.Methods {
                                        string_ids.push(method.MethodTitleId);
                                    }
                                }
                            }
                            // 0x5E: Catenate
                            uefi_parser::IfrOpcode::Catenate => {}
                            // 0x5F: GUID
                            uefi_parser::IfrOpcode::Guid => {
                                if let Ok((_, guid)) =
                                    uefi_parser::ifr_guid(operation.Data.unwrap())
                                {
                                    // This manual parsing here is ugly and can ultimately be done using nom,
                                    // but it's done already and not that important anyway
                                    match guid.Guid {
                                        uefi_parser::IFR_TIANO_GUID => {
                                            if let Ok((_, edk2)) =
                                                uefi_parser::ifr_guid_edk2(guid.Data)
                                            {
                                                match edk2.ExtendedOpCode {
                                                    uefi_parser::IfrEdk2ExtendOpCode::Banner => {
                                                        if let Ok((_, banner)) =
                                                            uefi_parser::ifr_guid_edk2_banner(
                                                                edk2.Data,
                                                            )
                                                        {
                                                            string_ids.push(banner.TitleId);
                                                        }
                                                    }
                                                    uefi_parser::IfrEdk2ExtendOpCode::Label => {}
                                                    uefi_parser::IfrEdk2ExtendOpCode::Timeout => {}
                                                    uefi_parser::IfrEdk2ExtendOpCode::Class => {}
                                                    uefi_parser::IfrEdk2ExtendOpCode::SubClass => {}
                                                    uefi_parser::IfrEdk2ExtendOpCode::Unknown(
                                                        _,
                                                    ) => {}
                                                }
                                            }
                                        }
                                        uefi_parser::IFR_FRAMEWORK_GUID => {
                                            if let Ok((_, edk)) =
                                                uefi_parser::ifr_guid_edk(guid.Data)
                                            {
                                                match edk.ExtendedOpCode {
                                                    uefi_parser::IfrEdkExtendOpCode::OptionKey => {}
                                                    uefi_parser::IfrEdkExtendOpCode::VarEqName => {
                                                        if edk.Data.len() == 2 {
                                                            let name_id = edk.Data[1] as u16 * 100
                                                                + edk.Data[0] as u16;
                                                            string_ids.push(name_id);
                                                        }
                                                    }
                                                    uefi_parser::IfrEdkExtendOpCode::Unknown(_) => {
                                                    }
                                                }
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                            }
                            // 0x60: Security
                            uefi_parser::IfrOpcode::Security => {}
                            // 0x61: ModalTag
                            uefi_parser::IfrOpcode::ModalTag => {}
                            // 0x62: RefreshId
                            uefi_parser::IfrOpcode::RefreshId => {}
                            // 0x63: WarningIf
                            uefi_parser::IfrOpcode::WarningIf => {
                                if let Ok((_, warn)) =
                                    uefi_parser::ifr_warning_if(operation.Data.unwrap())
                                {
                                    string_ids.push(warn.WarningStringId);
                                }
                            }
                            // 0x64: Match2
                            uefi_parser::IfrOpcode::Match2 => {}
                            // Unknown operation
                            uefi_parser::IfrOpcode::Unknown(_) => {}
                        }
                    }
                }

                // Find min and max StringId, and the number of unique ones
                string_ids.sort();
                string_ids.dedup();
                if string_ids.len() > 0 {
                    // Add the required information to forms
                    let form = (
                        i,
                        candidate.len(),
                        string_ids.len(),
                        *string_ids.first().unwrap(),
                        *string_ids.last().unwrap(),
                    );
                    forms.push(form);
                }

                i += candidate.len();
            } else {
                i += 1;
            }
        } else {
            i += 1;
        }
    }

    // No need to continue if no forms are found
    if forms.len() == 0 {
        return (Vec::new(), Vec::new());
    }

    // Construct return value
    let mut result_strings = Vec::new();
    let mut result_forms = Vec::new();
    for string in &strings {
        result_strings.push(StringPackage {
            offset: string.0,
            length: string.1,
            language: string.2.clone(),
            string_id_map: string.3.clone(),
        });
    }
    for form in &forms {
        result_forms.push(FormPackage {
            offset: form.0,
            length: form.1,
            used_strings: form.2,
            min_string_id: form.3,
            max_string_id: form.4,
        });
    }

    return (result_strings, result_forms);
}

fn uefi_ifr_extract(
    path: &OsStr,
    data: &[u8],
    form_package: &FormPackage,
    form_package_index: usize,
    string_package: &StringPackage,
    string_package_index: usize,
    verbose_mode: bool,
) -> () {
    let mut text = Vec::new();
    let strings_map = &string_package.string_id_map;

    if let Ok((_, candidate)) =
        uefi_parser::hii_form_package_candidate(&data[form_package.offset..])
    {
        if let Ok((_, package)) = uefi_parser::hii_package(candidate) {
            // Parse form package and output its structure as human-readable strings
            match uefi_parser::ifr_operations(package.Data.unwrap()) {
                Ok((_, operations)) => {
                    let mut scope_depth = 0;
                    let mut current_operation_offset = form_package.offset + 4; // Header size of UEFI HII form package is 4 bytes
                    for operation in &operations {
                        if operation.OpCode == uefi_parser::IfrOpcode::End {
                            if scope_depth >= 1 {
                                scope_depth -= 1;
                            }
                        }
                        
                        if verbose_mode {
                            write!(
                                &mut text,
                                "0x{:X}: ",
                                current_operation_offset
                            )
                            .unwrap();
                        }

                        write!(
                            &mut text,
                            "{:\t<1$}{2:?} ",
                            "", scope_depth, operation.OpCode
                        )
                        .unwrap();

                        if operation.ScopeStart == true {
                            scope_depth += 1;
                        }

                        match operation.OpCode {
                            // 0x01: Form
                            uefi_parser::IfrOpcode::Form => {
                                match uefi_parser::ifr_form(operation.Data.unwrap()) {
                                    Ok((_, form)) => {
                                        write!(
                                            &mut text,
                                            "FormId: 0x{:X}, Title: \"{}\"",
                                            form.FormId,
                                            strings_map
                                                .get(&form.TitleStringId)
                                                .unwrap_or(&String::from("InvalidId"))
                                        )
                                        .unwrap();
                                    }
                                    Err(e) => {
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("Form parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            // 0x02: Subtitle
                            uefi_parser::IfrOpcode::Subtitle => {
                                match uefi_parser::ifr_subtitle(operation.Data.unwrap()) {
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
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("Subtitle parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            // 0x03: Text
                            uefi_parser::IfrOpcode::Text => {
                                match uefi_parser::ifr_text(operation.Data.unwrap()) {
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
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("Text parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            // 0x04: Image
                            uefi_parser::IfrOpcode::Image => {
                                match uefi_parser::ifr_image(operation.Data.unwrap()) {
                                    Ok((_, image)) => {
                                        write!(&mut text, "ImageId: 0x{:X}", image.ImageId).unwrap();
                                    }
                                    Err(e) => {
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("Image parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            // 0x05: OneOf
                            uefi_parser::IfrOpcode::OneOf => {
                                match uefi_parser::ifr_one_of(operation.Data.unwrap()) {
                                    Ok((_, onf)) => {
                                        write!(&mut text, "Prompt: \"{}\", Help: \"{}\", QuestionFlags: 0x{:X}, QuestionId: 0x{:X}, VarStoreId: 0x{:X}, VarOffset: 0x{:X}, Flags: 0x{:X}, ", 
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
                                                "Size: 8, Min: 0x{:X}, Max: 0x{:X}, Step: 0x{:X}",
                                                onf.MinMaxStepData8[0].unwrap(),
                                                onf.MinMaxStepData8[1].unwrap(),
                                                onf.MinMaxStepData8[2].unwrap()
                                            )
                                            .unwrap();
                                        }
                                        if let Some(_) = onf.MinMaxStepData16[0] {
                                            write!(
                                                &mut text,
                                                "Size: 16, Min: 0x{:X}, Max: 0x{:X}, Step: 0x{:X}",
                                                onf.MinMaxStepData16[0].unwrap(),
                                                onf.MinMaxStepData16[1].unwrap(),
                                                onf.MinMaxStepData16[2].unwrap()
                                            )
                                            .unwrap();
                                        }
                                        if let Some(_) = onf.MinMaxStepData32[0] {
                                            write!(
                                                &mut text,
                                                "Size: 32, Min: 0x{:X}, Max: 0x{:X}, Step: 0x{:X}",
                                                onf.MinMaxStepData32[0].unwrap(),
                                                onf.MinMaxStepData32[1].unwrap(),
                                                onf.MinMaxStepData32[2].unwrap()
                                            )
                                            .unwrap();
                                        }
                                        if let Some(_) = onf.MinMaxStepData64[0] {
                                            write!(
                                                &mut text,
                                                "Size: 64, Min: 0x{:X}, Max: 0x{:X}, Step: 0x{:X}",
                                                onf.MinMaxStepData64[0].unwrap(),
                                                onf.MinMaxStepData64[1].unwrap(),
                                                onf.MinMaxStepData64[2].unwrap()
                                            )
                                            .unwrap();
                                        }
                                    }
                                    Err(e) => {
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("OneOf parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            // 0x06: CheckBox
                            uefi_parser::IfrOpcode::CheckBox => {
                                match uefi_parser::ifr_check_box(operation.Data.unwrap()) {
                                    Ok((_, cb)) => {
                                        write!(&mut text, "Prompt: \"{}\", Help: \"{}\", QuestionFlags: 0x{:X}, QuestionId: 0x{:X}, VarStoreId: 0x{:X}, VarOffset: 0x{:X}, Flags: 0x{:X}", 
                                                strings_map.get(&cb.PromptStringId).unwrap_or(&String::from("InvalidId")),
                                                strings_map.get(&cb.HelpStringId).unwrap_or(&String::from("InvalidId")),
                                                cb.QuestionFlags,
                                                cb.QuestionId,
                                                cb.VarStoreId,
                                                cb.VarStoreInfo,
                                                cb.Flags).unwrap();
                                    }
                                    Err(e) => {
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("CheckBox parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            // 0x07: Numeric
                            uefi_parser::IfrOpcode::Numeric => {
                                match uefi_parser::ifr_numeric(operation.Data.unwrap()) {
                                    Ok((_, num)) => {
                                        write!(&mut text, "Prompt: \"{}\", Help: \"{}\", QuestionFlags: 0x{:X}, QuestionId: 0x{:X}, VarStoreId: 0x{:X}, VarOffset: 0x{:X}, Flags: 0x{:X}, ", 
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
                                                "Size: 8, Min: 0x{:X}, Max: 0x{:X}, Step: 0x{:X}",
                                                num.MinMaxStepData8[0].unwrap(),
                                                num.MinMaxStepData8[1].unwrap(),
                                                num.MinMaxStepData8[2].unwrap()
                                            )
                                            .unwrap();
                                        }
                                        if let Some(_) = num.MinMaxStepData16[0] {
                                            write!(
                                                &mut text,
                                                "Size: 16, Min: 0x{:X}, Max: 0x{:X}, Step: 0x{:X}",
                                                num.MinMaxStepData16[0].unwrap(),
                                                num.MinMaxStepData16[1].unwrap(),
                                                num.MinMaxStepData16[2].unwrap()
                                            )
                                            .unwrap();
                                        }
                                        if let Some(_) = num.MinMaxStepData32[0] {
                                            write!(
                                                &mut text,
                                                "Size: 32, Min: 0x{:X}, Max: 0x{:X}, Step: 0x{:X}",
                                                num.MinMaxStepData32[0].unwrap(),
                                                num.MinMaxStepData32[1].unwrap(),
                                                num.MinMaxStepData32[2].unwrap()
                                            )
                                            .unwrap();
                                        }
                                        if let Some(_) = num.MinMaxStepData64[0] {
                                            write!(
                                                &mut text,
                                                "Size: 64, Min: 0x{:X}, Max: 0x{:X}, Step: 0x{:X}",
                                                num.MinMaxStepData64[0].unwrap(),
                                                num.MinMaxStepData64[1].unwrap(),
                                                num.MinMaxStepData64[2].unwrap()
                                            )
                                            .unwrap();
                                        }
                                    }
                                    Err(e) => {
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("Numeric parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            // 0x08: Password
                            uefi_parser::IfrOpcode::Password => {
                                match uefi_parser::ifr_password(operation.Data.unwrap()) {
                                    Ok((_, pw)) => {
                                        write!(&mut text, "Prompt: \"{}\", Help: \"{}\", QuestionFlags: 0x{:X}, QuestionId: 0x{:X}, VarStoreId: 0x{:X}, VarStoreInfo: 0x{:X}, MinSize: 0x{:X}, MaxSize: 0x{:X}", 
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
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("Password parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            // 0x09: OneOfOption
                            uefi_parser::IfrOpcode::OneOfOption => {
                                match uefi_parser::ifr_one_of_option(operation.Data.unwrap()) {
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
                                            uefi_parser::IfrTypeValue::String(x) => {
                                                write!(
                                                    &mut text,
                                                    "String: \"{}\"",
                                                    strings_map
                                                        .get(&x)
                                                        .unwrap_or(&String::from("InvalidId"))
                                                )
                                                .unwrap();
                                            }
                                            uefi_parser::IfrTypeValue::Action(x) => {
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
                                                write!(&mut text, "Value: {}", opt.Value).unwrap();
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("OneOfOption parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            // 0x0A: SuppressIf
                            uefi_parser::IfrOpcode::SuppressIf => {}
                            // 0x0B: Locked
                            uefi_parser::IfrOpcode::Locked => {}
                            // 0x0C: Action
                            uefi_parser::IfrOpcode::Action => {
                                match uefi_parser::ifr_action(operation.Data.unwrap()) {
                                    Ok((_, act)) => {
                                        write!(&mut text, "Prompt: \"{}\", Help: \"{}\", QuestionFlags: 0x{:X}, QuestionId: 0x{:X}, VarStoreId: 0x{:X}, VarStoreInfo: 0x{:X}", 
                                                strings_map.get(&act.PromptStringId).unwrap_or(&String::from("InvalidId")),
                                                strings_map.get(&act.HelpStringId).unwrap_or(&String::from("InvalidId")),
                                                act.QuestionFlags,
                                                act.QuestionId,
                                                act.VarStoreId,
                                                act.VarStoreInfo).unwrap();
                                        if let Some(x) = act.ConfigStringId {
                                            write!(
                                                &mut text,
                                                ", QuestionConfig: \"{}\"",
                                                strings_map
                                                    .get(&x)
                                                    .unwrap_or(&String::from("InvalidId"))
                                            )
                                            .unwrap();
                                        }
                                    }
                                    Err(e) => {
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("Action parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            // 0x0D: ResetButton
                            uefi_parser::IfrOpcode::ResetButton => {
                                match uefi_parser::ifr_reset_button(operation.Data.unwrap()) {
                                    Ok((_, rst)) => {
                                        write!(
                                            &mut text,
                                            "Prompt: \"{}\", Help: \"{}\", DefaultId: 0x{:X}",
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
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("ResetButton parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            // 0x0E: FormSet
                            uefi_parser::IfrOpcode::FormSet => {
                                match uefi_parser::ifr_form_set(operation.Data.unwrap()) {
                                    Ok((_, form_set)) => {
                                        write!(
                                            &mut text,
                                            "Guid: {}, Title: \"{}\", Help: \"{}\"",
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
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("FormSet parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            // 0x0F: Ref
                            uefi_parser::IfrOpcode::Ref => {
                                match uefi_parser::ifr_ref(operation.Data.unwrap()) {
                                    Ok((_, rf)) => {
                                        write!(&mut text, "Prompt: \"{}\", Help: \"{}\", QuestionFlags: 0x{:X}, QuestionId: 0x{:X}, VarStoreId: 0x{:X}, VarStoreInfo: 0x{:X}", 
                                                strings_map.get(&rf.PromptStringId).unwrap_or(&String::from("InvalidId")),
                                                strings_map.get(&rf.HelpStringId).unwrap_or(&String::from("InvalidId")),
                                                rf.QuestionFlags,
                                                rf.QuestionId,
                                                rf.VarStoreId,
                                                rf.VarStoreInfo).unwrap();
                                        if let Some(x) = rf.FormId {
                                            write!(&mut text, ", FormId: 0x{:X}", x).unwrap();
                                        }
                                        if let Some(x) = rf.RefQuestionId {
                                            write!(&mut text, ", RefQuestionId: 0x{:X}", x).unwrap();
                                        }
                                        if let Some(x) = rf.FormSetGuid {
                                            write!(&mut text, ", FormSetGuid: {}", x).unwrap();
                                        }
                                        if let Some(x) = rf.DevicePathId {
                                            write!(&mut text, ", DevicePathId: 0x{:X}", x).unwrap();
                                        }
                                    }
                                    Err(e) => {
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("Ref parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            // 0x10: NoSubmitIf
                            uefi_parser::IfrOpcode::NoSubmitIf => {
                                match uefi_parser::ifr_no_submit_if(operation.Data.unwrap()) {
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
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("NoSubmitIf parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            // 0x11: InconsistentIf
                            uefi_parser::IfrOpcode::InconsistentIf => {
                                match uefi_parser::ifr_inconsistent_if(operation.Data.unwrap()) {
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
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("InconsistentIf parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            // 0x12: EqIdVal
                            uefi_parser::IfrOpcode::EqIdVal => {
                                match uefi_parser::ifr_eq_id_val(operation.Data.unwrap()) {
                                    Ok((_, eq)) => {
                                        write!(
                                            &mut text,
                                            "QuestionId: 0x{:X}, Value: 0x{:X}",
                                            eq.QuestionId, eq.Value
                                        )
                                        .unwrap();
                                    }
                                    Err(e) => {
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!(" EqIdVal parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            // 0x13: EqIdId
                            uefi_parser::IfrOpcode::EqIdId => {
                                match uefi_parser::ifr_eq_id_id(operation.Data.unwrap()) {
                                    Ok((_, eq)) => {
                                        write!(
                                            &mut text,
                                            "QuestionId: 0x{:X}, OtherQuestionId: 0x{:X}",
                                            eq.QuestionId, eq.OtherQuestionId
                                        )
                                        .unwrap();
                                    }
                                    Err(e) => {
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("EqIdId parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            // 0x14: EqIdValList
                            uefi_parser::IfrOpcode::EqIdValList => {
                                match uefi_parser::ifr_eq_id_val_list(operation.Data.unwrap()) {
                                    Ok((_, eql)) => {
                                        write!(
                                            &mut text,
                                            "QuestionId: 0x{:X}, Values: {:?}",
                                            eql.QuestionId, eql.Values
                                        )
                                        .unwrap();
                                    }
                                    Err(e) => {
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("EqIdValList parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            // 0x15: And
                            uefi_parser::IfrOpcode::And => {}
                            // 0x16: Or
                            uefi_parser::IfrOpcode::Or => {}
                            // 0x17: Not
                            uefi_parser::IfrOpcode::Not => {}
                            // 0x18: Rule
                            uefi_parser::IfrOpcode::Rule => {
                                match uefi_parser::ifr_rule(operation.Data.unwrap()) {
                                    Ok((_, rule)) => {
                                        write!(&mut text, "RuleId: 0x{:X}", rule.RuleId).unwrap();
                                    }
                                    Err(e) => {
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("Rule parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            // 0x19: GrayOutIf
                            uefi_parser::IfrOpcode::GrayOutIf => {}
                            // 0x1A: Date
                            uefi_parser::IfrOpcode::Date => {
                                match uefi_parser::ifr_date(operation.Data.unwrap()) {
                                    Ok((_, dt)) => {
                                        write!(&mut text, "Prompt: \"{}\", Help: \"{}\", QuestionFlags: 0x{:X}, QuestionId: 0x{:X}, VarStoreId: 0x{:X}, VarStoreInfo: 0x{:X}, Flags: 0x{:X}", 
                                                strings_map.get(&dt.PromptStringId).unwrap_or(&String::from("InvalidId")),
                                                strings_map.get(&dt.HelpStringId).unwrap_or(&String::from("InvalidId")),
                                                dt.QuestionFlags,
                                                dt.QuestionId,
                                                dt.VarStoreId,
                                                dt.VarStoreInfo,
                                                dt.Flags).unwrap();
                                    }
                                    Err(e) => {
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("Date parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            // 0x1B: Time
                            uefi_parser::IfrOpcode::Time => {
                                match uefi_parser::ifr_time(operation.Data.unwrap()) {
                                    Ok((_, time)) => {
                                        write!(&mut text, "Prompt: \"{}\", Help: \"{}\", QuestionFlags: 0x{:X}, QuestionId: 0x{:X}, VarStoreId: 0x{:X}, VarStoreInfo: 0x{:X}, Flags: 0x{:X}", 
                                                strings_map.get(&time.PromptStringId).unwrap_or(&String::from("InvalidId")),
                                                strings_map.get(&time.HelpStringId).unwrap_or(&String::from("InvalidId")),
                                                time.QuestionFlags,
                                                time.QuestionId,
                                                time.VarStoreId,
                                                time.VarStoreInfo,
                                                time.Flags).unwrap();
                                    }
                                    Err(e) => {
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("Time parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            // 0x1C: String
                            uefi_parser::IfrOpcode::String => {
                                match uefi_parser::ifr_string(operation.Data.unwrap()) {
                                    Ok((_, st)) => {
                                        write!(&mut text, "Prompt: \"{}\", Help: \"{}\", QuestionFlags: 0x{:X}, QuestionId: 0x{:X}, VarStoreId: 0x{:X}, VarStoreInfo: 0x{:X}, MinSize: 0x{:X}, MaxSize: 0x{:X}, Flags: 0x{:X}", 
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
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("String parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            // 0x1D: Refresh
                            uefi_parser::IfrOpcode::Refresh => {
                                match uefi_parser::ifr_refresh(operation.Data.unwrap()) {
                                    Ok((_, refr)) => {
                                        write!(
                                            &mut text,
                                            "RefreshInterval: 0x{:X}",
                                            refr.RefreshInterval
                                        )
                                        .unwrap();
                                    }
                                    Err(e) => {
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("Refresh parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            // 0x1E: DisableIf
                            uefi_parser::IfrOpcode::DisableIf => {}
                            // 0x1F: Animation
                            uefi_parser::IfrOpcode::Animation => {
                                match uefi_parser::ifr_animation(operation.Data.unwrap()) {
                                    Ok((_, anim)) => {
                                        write!(&mut text, "AnimationId: 0x{:X}", anim.AnimationId)
                                            .unwrap();
                                    }
                                    Err(e) => {
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("Animation parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            // 0x20: ToLower
                            uefi_parser::IfrOpcode::ToLower => {}
                            // 0x21: ToUpper
                            uefi_parser::IfrOpcode::ToUpper => {}
                            // 0x22: Map
                            uefi_parser::IfrOpcode::Map => {}
                            // 0x23: OrderedList
                            uefi_parser::IfrOpcode::OrderedList => {
                                match uefi_parser::ifr_ordered_list(operation.Data.unwrap()) {
                                    Ok((_, ol)) => {
                                        write!(&mut text, "Prompt: \"{}\", Help: \"{}\", QuestionFlags: 0x{:X}, QuestionId: 0x{:X}, VarStoreId: 0x{:X}, VarOffset: 0x{:X}, MaxContainers: 0x{:X}, Flags: 0x{:X}", 
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
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("OrderedList parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            // 0x24: VarStore
                            uefi_parser::IfrOpcode::VarStore => {
                                match uefi_parser::ifr_var_store(operation.Data.unwrap()) {
                                    Ok((_, var_store)) => {
                                        write!(
                                            &mut text,
                                            "Guid: {}, VarStoreId: 0x{:X}, Size: 0x{:X}, Name: \"{}\"",
                                            var_store.Guid,
                                            var_store.VarStoreId,
                                            var_store.Size,
                                            var_store.Name
                                        )
                                        .unwrap();
                                    }
                                    Err(e) => {
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("VarStore parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            // 0x25: VarStoreNameValue
                            uefi_parser::IfrOpcode::VarStoreNameValue => {
                                match uefi_parser::ifr_var_store_name_value(operation.Data.unwrap())
                                {
                                    Ok((_, var_store)) => {
                                        write!(
                                            &mut text,
                                            "Guid: {}, VarStoreId: 0x{:X}",
                                            var_store.Guid, var_store.VarStoreId
                                        )
                                        .unwrap();
                                    }
                                    Err(e) => {
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("VarStoreNameValue parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            // 0x26: VarStoreEfi
                            uefi_parser::IfrOpcode::VarStoreEfi => {
                                match uefi_parser::ifr_var_store_efi(operation.Data.unwrap()) {
                                    Ok((_, var_store)) => {
                                        write!(&mut text, "Guid: {}, VarStoreId: 0x{:X}, Attributes: 0x{:X}", 
                                                var_store.Guid,
                                                var_store.VarStoreId,
                                                var_store.Attributes
                                        ).unwrap();

                                        if let Some(size) = var_store.Size {
                                            write!(&mut text, ", Size: 0x{:X}", 
                                                size
                                            ).unwrap();
                                        }

                                        if let Some(name) = var_store.Name {
                                            write!(&mut text, ", Name: \"{}\"", 
                                                name
                                            ).unwrap();
                                        }
                                    }
                                    Err(e) => {
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("VarStoreEfi parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            // 0x27: VarStoreDevice
                            uefi_parser::IfrOpcode::VarStoreDevice => {
                                match uefi_parser::ifr_var_store_device(operation.Data.unwrap()) {
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
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("VarStoreDevice parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            // 0x28: Version
                            uefi_parser::IfrOpcode::Version => {}
                            // 0x29: End
                            uefi_parser::IfrOpcode::End => {}
                            // 0x2A: Match
                            uefi_parser::IfrOpcode::Match => {}
                            // 0x2B: Get
                            uefi_parser::IfrOpcode::Get => {
                                match uefi_parser::ifr_get(operation.Data.unwrap()) {
                                    Ok((_, get)) => {
                                        write!(
                                            &mut text,
                                            "VarStoreId: 0x{:X}, VarStoreInfo: 0x{:X}, VarStoreType: 0x{:X}",
                                            get.VarStoreId, get.VarStoreInfo, get.VarStoreType
                                        )
                                        .unwrap();
                                    }
                                    Err(e) => {
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("Get parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            // 0x2C: Set
                            uefi_parser::IfrOpcode::Set => {
                                match uefi_parser::ifr_set(operation.Data.unwrap()) {
                                    Ok((_, set)) => {
                                        write!(
                                            &mut text,
                                            "VarStoreId: 0x{:X}, VarStoreInfo: 0x{:X}, VarStoreType: 0x{:X}",
                                            set.VarStoreId, set.VarStoreInfo, set.VarStoreType
                                        )
                                        .unwrap();
                                    }
                                    Err(e) => {
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("Set parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            // 0x2D: Read
                            uefi_parser::IfrOpcode::Read => {}
                            // 0x2E: Write
                            uefi_parser::IfrOpcode::Write => {}
                            // 0x2F: Equal
                            uefi_parser::IfrOpcode::Equal => {}
                            // 0x30: NotEqual
                            uefi_parser::IfrOpcode::NotEqual => {}
                            // 0x31: GreaterThan
                            uefi_parser::IfrOpcode::GreaterThan => {}
                            // 0x32: GreaterEqual
                            uefi_parser::IfrOpcode::GreaterEqual => {}
                            // 0x33: LessThan
                            uefi_parser::IfrOpcode::LessThan => {}
                            // 0x34: LessEqual
                            uefi_parser::IfrOpcode::LessEqual => {}
                            // 0x35: BitwiseAnd
                            uefi_parser::IfrOpcode::BitwiseAnd => {}
                            // 0x36: BitwiseOr
                            uefi_parser::IfrOpcode::BitwiseOr => {}
                            // 0x37: BitwiseNot
                            uefi_parser::IfrOpcode::BitwiseNot => {}
                            // 0x38: ShiftLeft
                            uefi_parser::IfrOpcode::ShiftLeft => {}
                            // 0x39: ShiftRight
                            uefi_parser::IfrOpcode::ShiftRight => {}
                            // 0x3A: Add
                            uefi_parser::IfrOpcode::Add => {}
                            // 0x3B: Substract
                            uefi_parser::IfrOpcode::Substract => {}
                            // 0x3C: Multiply
                            uefi_parser::IfrOpcode::Multiply => {}
                            // 0x3D: Divide
                            uefi_parser::IfrOpcode::Divide => {}
                            // 0x3E: Modulo
                            uefi_parser::IfrOpcode::Modulo => {}
                            // 0x3F: RuleRef
                            uefi_parser::IfrOpcode::RuleRef => {
                                match uefi_parser::ifr_rule_ref(operation.Data.unwrap()) {
                                    Ok((_, rule)) => {
                                        write!(&mut text, "RuleId: 0x{:X}", rule.RuleId).unwrap();
                                    }
                                    Err(e) => {
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("RuleRef parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            // 0x40: QuestionRef1
                            uefi_parser::IfrOpcode::QuestionRef1 => {
                                match uefi_parser::ifr_question_ref_1(operation.Data.unwrap()) {
                                    Ok((_, qr)) => {
                                        write!(&mut text, "QuestionId: 0x{:X}", qr.QuestionId).unwrap();
                                    }
                                    Err(e) => {
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("QuestionRef1 parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            // 0x41: QuestionRef2
                            uefi_parser::IfrOpcode::QuestionRef2 => {}
                            // 0x42: Uint8
                            uefi_parser::IfrOpcode::Uint8 => {
                                match uefi_parser::ifr_uint8(operation.Data.unwrap()) {
                                    Ok((_, u)) => {
                                        write!(&mut text, "Value: 0x{:X}", u.Value).unwrap();
                                    }
                                    Err(e) => {
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("Uint8 parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            // 0x43: Uint16
                            uefi_parser::IfrOpcode::Uint16 => {
                                match uefi_parser::ifr_uint16(operation.Data.unwrap()) {
                                    Ok((_, u)) => {
                                        write!(&mut text, "Value: 0x{:X}", u.Value).unwrap();
                                    }
                                    Err(e) => {
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("Uint16 parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            // 0x44: Uint32
                            uefi_parser::IfrOpcode::Uint32 => {
                                match uefi_parser::ifr_uint32(operation.Data.unwrap()) {
                                    Ok((_, u)) => {
                                        write!(&mut text, "Value: 0x{:X}", u.Value).unwrap();
                                    }
                                    Err(e) => {
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("Uint32 parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            // 0x45: Uint64
                            uefi_parser::IfrOpcode::Uint64 => {
                                match uefi_parser::ifr_uint64(operation.Data.unwrap()) {
                                    Ok((_, u)) => {
                                        write!(&mut text, "Value: 0x{:X}", u.Value).unwrap();
                                    }
                                    Err(e) => {
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("Uint64 parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            // 0x46: True
                            uefi_parser::IfrOpcode::True => {}
                            // 0x47: False
                            uefi_parser::IfrOpcode::False => {}
                            // 0x48: ToUint
                            uefi_parser::IfrOpcode::ToUint => {}
                            // 0x49: ToString
                            uefi_parser::IfrOpcode::ToString => {
                                match uefi_parser::ifr_to_string(operation.Data.unwrap()) {
                                    Ok((_, ts)) => {
                                        write!(&mut text, "Format: 0x{:X}", ts.Format).unwrap();
                                    }
                                    Err(e) => {
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("ToString parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            // 0x4A: ToBoolean
                            uefi_parser::IfrOpcode::ToBoolean => {}
                            // 0x4B: Mid
                            uefi_parser::IfrOpcode::Mid => {}
                            // 0x4C: Find
                            uefi_parser::IfrOpcode::Find => {
                                match uefi_parser::ifr_find(operation.Data.unwrap()) {
                                    Ok((_, fnd)) => {
                                        write!(&mut text, "Format: 0x{:X}", fnd.Format).unwrap();
                                    }
                                    Err(e) => {
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("Find parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            // 0x4D: Token
                            uefi_parser::IfrOpcode::Token => {}
                            // 0x4E: StringRef1
                            uefi_parser::IfrOpcode::StringRef1 => {
                                match uefi_parser::ifr_string_ref_1(operation.Data.unwrap()) {
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
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("StringRef1 parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            // 0x4F: StringRef2
                            uefi_parser::IfrOpcode::StringRef2 => {}
                            // 0x50: Conditional
                            uefi_parser::IfrOpcode::Conditional => {}
                            // 0x51: QuestionRef3
                            uefi_parser::IfrOpcode::QuestionRef3 => {
                                if let Some(_) = operation.Data {
                                    match uefi_parser::ifr_question_ref_3(operation.Data.unwrap()) {
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
                                                "RawData: {:02X?}",
                                                operation.Data.unwrap()
                                            )
                                            .unwrap();
                                            println!("QuestionRef3 parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                        }
                                    }
                                }
                            }
                            // 0x52: Zero
                            uefi_parser::IfrOpcode::Zero => {}
                            // 0x53: One
                            uefi_parser::IfrOpcode::One => {}
                            // 0x54: Ones
                            uefi_parser::IfrOpcode::Ones => {}
                            // 0x55: Undefined
                            uefi_parser::IfrOpcode::Undefined => {}
                            // 0x56: Length
                            uefi_parser::IfrOpcode::Length => {}
                            // 0x57: Dup
                            uefi_parser::IfrOpcode::Dup => {}
                            // 0x58: This
                            uefi_parser::IfrOpcode::This => {}
                            // 0x59: Span
                            uefi_parser::IfrOpcode::Span => {
                                match uefi_parser::ifr_span(operation.Data.unwrap()) {
                                    Ok((_, span)) => {
                                        write!(&mut text, "Flags: 0x{:X}", span.Flags).unwrap();
                                    }
                                    Err(e) => {
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("Span parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            // 0x5A: Value
                            uefi_parser::IfrOpcode::Value => {}
                            // 0x5B: Default
                            uefi_parser::IfrOpcode::Default => {
                                match uefi_parser::ifr_default(operation.Data.unwrap()) {
                                    Ok((_, def)) => {
                                        write!(&mut text, "DefaultId: 0x{:X} ", def.DefaultId).unwrap();
                                        match def.Value {
                                            uefi_parser::IfrTypeValue::String(x) => {
                                                write!(
                                                    &mut text,
                                                    "String: \"{}\"",
                                                    strings_map
                                                        .get(&x)
                                                        .unwrap_or(&String::from("InvalidId"))
                                                )
                                                .unwrap();
                                            }
                                            uefi_parser::IfrTypeValue::Action(x) => {
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
                                                write!(&mut text, "Value: {}", def.Value).unwrap();
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("Default parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            // 0x5C: DefaultStore
                            uefi_parser::IfrOpcode::DefaultStore => {
                                match uefi_parser::ifr_default_store(operation.Data.unwrap()) {
                                    Ok((_, default_store)) => {
                                        write!(
                                            &mut text,
                                            "DefaultId: 0x{:X}, Name: \"{}\"",
                                            default_store.DefaultId,
                                            strings_map
                                                .get(&default_store.NameStringId)
                                                .unwrap_or(&String::from("InvalidId"))
                                        )
                                        .unwrap();
                                    }
                                    Err(e) => {
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("DefaultStore parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            // 0x5D: FormMap
                            uefi_parser::IfrOpcode::FormMap => {
                                match uefi_parser::ifr_form_map(operation.Data.unwrap()) {
                                    Ok((_, form_map)) => {
                                        write!(&mut text, "FormId: 0x{:X}", form_map.FormId).unwrap();
                                        for method in form_map.Methods {
                                            write!(
                                                &mut text,
                                                "| Guid: {}, Method: \"{}\"",
                                                method.MethodIdentifier,
                                                strings_map
                                                    .get(&method.MethodTitleId)
                                                    .unwrap_or(&String::from("InvalidId"))
                                            )
                                            .unwrap();
                                        }
                                    }
                                    Err(e) => {
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("FormMap parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            // 0x5E: Catenate
                            uefi_parser::IfrOpcode::Catenate => {}
                            // 0x5F: GUID
                            uefi_parser::IfrOpcode::Guid => {
                                match uefi_parser::ifr_guid(operation.Data.unwrap()) {
                                    Ok((_, guid)) => {
                                        // This manual parsing here is ugly and can ultimately be done using nom,
                                        // but it's done already and not that important anyway
                                        // TODO: refactor later
                                        let mut done = false;
                                        match guid.Guid {
                                            uefi_parser::IFR_TIANO_GUID => {
                                                if let Ok((_, edk2)) =
                                                    uefi_parser::ifr_guid_edk2(guid.Data)
                                                {
                                                    match edk2.ExtendedOpCode {
                                                        uefi_parser::IfrEdk2ExtendOpCode::Banner => {
                                                            if let Ok((_, banner)) =
                                                                uefi_parser::ifr_guid_edk2_banner(
                                                                    edk2.Data,
                                                                )
                                                            {
                                                                write!(&mut text, "Guid: {}, ExtendedOpCode: {:?}, Title: \"{}\", LineNumber: 0x{:X}, Alignment: 0x{:X} ", 
                                                                    guid.Guid,
                                                                    edk2.ExtendedOpCode,
                                                                    strings_map.get(&banner.TitleId).unwrap_or(&String::from("InvalidId")),
                                                                    banner.LineNumber,
                                                                    banner.Alignment).unwrap();
                                                                done = true;
                                                            }
                                                        }
                                                        uefi_parser::IfrEdk2ExtendOpCode::Label => {
                                                            if edk2.Data.len() == 2 {
                                                                write!(&mut text, "Guid: {}, ExtendedOpCode: {:?}, LabelNumber: 0x{:X}", 
                                                                        guid.Guid,
                                                                        edk2.ExtendedOpCode,
                                                                        edk2.Data[1] as u16 * 100 + edk2.Data[0] as u16).unwrap();
                                                                done = true;
                                                            }
                                                        }
                                                        uefi_parser::IfrEdk2ExtendOpCode::Timeout => {
                                                            if edk2.Data.len() == 2 {
                                                                write!(&mut text, "Guid: {}, ExtendedOpCode: {:?}, Timeout: 0x{:X}", 
                                                                        guid.Guid,
                                                                        edk2.ExtendedOpCode,
                                                                        edk2.Data[1] as u16 * 100 + edk2.Data[0] as u16).unwrap();
                                                                done = true;
                                                            }
                                                        }
                                                        uefi_parser::IfrEdk2ExtendOpCode::Class => {
                                                            if edk2.Data.len() == 2 {
                                                                write!(&mut text, "Guid: {}, ExtendedOpCode: {:?}, Class: 0x{:X}", 
                                                                        guid.Guid,
                                                                        edk2.ExtendedOpCode,
                                                                        edk2.Data[1] as u16 * 100 + edk2.Data[0] as u16).unwrap();
                                                                done = true;
                                                            }
                                                        }
                                                        uefi_parser::IfrEdk2ExtendOpCode::SubClass => {
                                                            if edk2.Data.len() == 2 {
                                                                write!(&mut text, "Guid: {}, ExtendedOpCode: {:?}, SubClass: 0x{:X}", 
                                                                        guid.Guid,
                                                                        edk2.ExtendedOpCode,
                                                                        edk2.Data[1] as u16 * 100 + edk2.Data[0] as u16).unwrap();
                                                                done = true;
                                                            }
                                                        }
                                                        uefi_parser::IfrEdk2ExtendOpCode::Unknown(_) => {
                                                        }
                                                    }
                                                }
                                            }
                                            uefi_parser::IFR_FRAMEWORK_GUID => {
                                                if let Ok((_, edk)) =
                                                    uefi_parser::ifr_guid_edk(guid.Data)
                                                {
                                                    match edk.ExtendedOpCode {
                                                        uefi_parser::IfrEdkExtendOpCode::OptionKey => {
                                                            write!(&mut text, "Guid: {}, ExtendedOpCode: {:?}, QuestionId: 0x{:X}, Data: {:?}", 
                                                                        guid.Guid,
                                                                        edk.ExtendedOpCode,
                                                                        edk.QuestionId,
                                                                        edk.Data).unwrap();
                                                            done = true;
                                                        }
                                                        uefi_parser::IfrEdkExtendOpCode::VarEqName => {
                                                            if edk.Data.len() == 2 {
                                                                let name_id = edk.Data[1] as u16
                                                                    * 100
                                                                    + edk.Data[0] as u16;
                                                                write!(&mut text, "Guid: {}, ExtendedOpCode: {:?}, QuestionId: 0x{:X}, Name: \"{}\"", 
                                                                        guid.Guid,
                                                                        edk.ExtendedOpCode,
                                                                        edk.QuestionId,
                                                                        strings_map.get(&name_id).unwrap_or(&String::from("InvalidId"))).unwrap();
                                                                done = true;
                                                            }
                                                        }
                                                        uefi_parser::IfrEdkExtendOpCode::Unknown(_) => {}
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
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("Guid parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            // 0x60: Security
                            uefi_parser::IfrOpcode::Security => {
                                match uefi_parser::ifr_security(operation.Data.unwrap()) {
                                    Ok((_, sec)) => {
                                        write!(&mut text, "Guid: {}", sec.Guid).unwrap();
                                    }
                                    Err(e) => {
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("Security parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            // 0x61: ModalTag
                            uefi_parser::IfrOpcode::ModalTag => {}
                            // 0x62: RefreshId
                            uefi_parser::IfrOpcode::RefreshId => {
                                match uefi_parser::ifr_refresh_id(operation.Data.unwrap()) {
                                    Ok((_, rid)) => {
                                        write!(&mut text, "Guid: {}", rid.Guid).unwrap();
                                    }
                                    Err(e) => {
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("RefreshId parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            // 0x63: WarningIf
                            uefi_parser::IfrOpcode::WarningIf => {
                                match uefi_parser::ifr_warning_if(operation.Data.unwrap()) {
                                    Ok((_, warn)) => {
                                        write!(
                                            &mut text,
                                            "Timeout: 0x{:X}, Warning: \"{}\"",
                                            warn.Timeout,
                                            strings_map
                                                .get(&warn.WarningStringId)
                                                .unwrap_or(&String::from("InvalidId"))
                                        )
                                        .unwrap();
                                    }
                                    Err(e) => {
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("WarningIf parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            // 0x64: Match2
                            uefi_parser::IfrOpcode::Match2 => {
                                match uefi_parser::ifr_match_2(operation.Data.unwrap()) {
                                    Ok((_, m2)) => {
                                        write!(&mut text, "Guid: {}", m2.Guid).unwrap();
                                    }
                                    Err(e) => {
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("Match2 parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            // Unknown operation
                            uefi_parser::IfrOpcode::Unknown(x) => {
                                write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                    .unwrap();
                                println!("IFR operation of unknown type 0x{:X}", x);
                            }
                        }
                        current_operation_offset += operation.Length as usize;

                        if verbose_mode {
                            write!(&mut text, " {}", operation).unwrap();
                        }

                        writeln!(&mut text, "").unwrap();
                    }
                }
                Err(e) => {
                    println!("IFR operations parse error: {:?}", e);
                }
            }
        }
    }

    // Write the result
    let mut file_path = OsString::new();
    file_path.push(path);
    file_path.push(".");
    file_path.push(form_package_index.to_string());
    file_path.push(".");
    file_path.push(string_package_index.to_string());
    file_path.push(".");
    file_path.push(string_package.language.clone());
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

//
// Framework HII parsing
//
fn framework_find_string_and_form_packages(data: &[u8]) -> (Vec<StringPackage>, Vec<FormPackage>) {
    let mut strings = Vec::new(); // String-to-id maps for all found string packages

    // Search for all string packages in the input file
    let mut i = 0;
    while i < data.len() {
        if let Ok((_, candidate)) = framework_parser::hii_string_package_candidate(&data[i..]) {
            if let Ok((_, package)) = framework_parser::hii_package(candidate) {
                if let Ok((_, string_package)) =
                    framework_parser::hii_string_package(package.Data.unwrap())
                {
                    let mut string_id_map = HashMap::new(); // Map of StringIds to strings
                    let mut current_string_index = 0;
                    let mut language = String::from("Invalid");
                    for string in &string_package.Strings {
                        // This will always work in a properly formatted string package
                        if string_package.StringPointers[current_string_index]
                            == string_package.LanguageNameStringOffset
                        {
                            language = string_package.Strings[current_string_index].clone();
                        }

                        string_id_map.insert(current_string_index as u16, string.clone());
                        current_string_index += 1;
                    }

                    // Add string
                    let string = (i, candidate.len(), language, string_id_map);
                    strings.push(string);

                    i += candidate.len();
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

    // No need to continue if there are no string packages found
    if strings.len() == 0 {
        return (Vec::new(), Vec::new());
    }

    //
    // Search for all form packages in the input file
    //
    let mut forms = Vec::new();
    i = 0;
    while i < data.len() {
        if let Ok((_, candidate)) = framework_parser::hii_form_package_candidate(&data[i..]) {
            if let Ok((_, package)) = framework_parser::hii_package(candidate) {
                // Parse form package and obtain StringIds
                let mut string_ids: Vec<u16> = Vec::new();
                if let Ok((_, operations)) = framework_parser::ifr_operations(package.Data.unwrap())
                {
                    //let mut current_operation: usize = 0;
                    for operation in &operations {
                        //current_operation += 1;
                        //println!("Operation #{}, OpCode: {:?}, Length 0x{:X}", current_operation, operation.OpCode, operation.Length);
                        match operation.OpCode {
                            framework_parser::IfrOpcode::Form => {
                                if let Ok((_, form)) =
                                    framework_parser::ifr_form(operation.Data.unwrap())
                                {
                                    string_ids.push(form.TitleStringId);
                                }
                            }
                            framework_parser::IfrOpcode::Subtitle => {
                                if let Ok((_, subtitile)) =
                                    framework_parser::ifr_subtitle(operation.Data.unwrap())
                                {
                                    string_ids.push(subtitile.SubtitleStringId);
                                }
                            }
                            framework_parser::IfrOpcode::Text => {
                                if let Ok((_, text)) =
                                    framework_parser::ifr_text(operation.Data.unwrap())
                                {
                                    string_ids.push(text.HelpStringId);
                                    string_ids.push(text.TextStringId);
                                    string_ids.push(text.TextTwoStringId);
                                }
                            }
                            framework_parser::IfrOpcode::Graphic => {}
                            framework_parser::IfrOpcode::OneOf => {
                                if let Ok((_, oneof)) =
                                    framework_parser::ifr_one_of(operation.Data.unwrap())
                                {
                                    string_ids.push(oneof.PromptStringId);
                                    string_ids.push(oneof.HelpStringId);
                                }
                            }
                            framework_parser::IfrOpcode::CheckBox => {
                                if let Ok((_, checkbox)) =
                                    framework_parser::ifr_check_box(operation.Data.unwrap())
                                {
                                    string_ids.push(checkbox.PromptStringId);
                                    string_ids.push(checkbox.HelpStringId);
                                }
                            }
                            framework_parser::IfrOpcode::Numeric => {
                                if let Ok((_, numeric)) =
                                    framework_parser::ifr_numeric(operation.Data.unwrap())
                                {
                                    string_ids.push(numeric.PromptStringId);
                                    string_ids.push(numeric.HelpStringId);
                                }
                            }
                            framework_parser::IfrOpcode::Password => {
                                if let Ok((_, password)) =
                                    framework_parser::ifr_password(operation.Data.unwrap())
                                {
                                    string_ids.push(password.PromptStringId);
                                    string_ids.push(password.HelpStringId);
                                }
                            }
                            framework_parser::IfrOpcode::OneOfOption => {
                                if let Ok((_, oneofoption)) =
                                    framework_parser::ifr_one_of_option(operation.Data.unwrap())
                                {
                                    string_ids.push(oneofoption.OptionStringId);
                                }
                            }
                            framework_parser::IfrOpcode::SuppressIf => {}
                            framework_parser::IfrOpcode::EndForm => {}
                            framework_parser::IfrOpcode::Hidden => {}
                            framework_parser::IfrOpcode::EndFormSet => {}
                            framework_parser::IfrOpcode::FormSet => {
                                if let Ok((_, formset)) =
                                    framework_parser::ifr_form_set(operation.Data.unwrap())
                                {
                                    string_ids.push(formset.TitleStringId);
                                    string_ids.push(formset.HelpStringId);
                                }
                            }
                            framework_parser::IfrOpcode::Ref => {
                                if let Ok((_, rf)) =
                                    framework_parser::ifr_ref(operation.Data.unwrap())
                                {
                                    string_ids.push(rf.PromptStringId);
                                    string_ids.push(rf.HelpStringId);
                                }
                            }
                            framework_parser::IfrOpcode::End => {}
                            framework_parser::IfrOpcode::InconsistentIf => {
                                if let Ok((_, incif)) =
                                    framework_parser::ifr_inconsistent_if(operation.Data.unwrap())
                                {
                                    string_ids.push(incif.PopupStringId);
                                }
                            }
                            framework_parser::IfrOpcode::EqIdVal => {}
                            framework_parser::IfrOpcode::EqIdId => {}
                            framework_parser::IfrOpcode::EqIdList => {}
                            framework_parser::IfrOpcode::And => {}
                            framework_parser::IfrOpcode::Or => {}
                            framework_parser::IfrOpcode::Not => {}
                            framework_parser::IfrOpcode::EndIf => {}
                            framework_parser::IfrOpcode::GrayOutIf => {}
                            framework_parser::IfrOpcode::Date => {
                                if let Ok((_, date)) =
                                    framework_parser::ifr_date(operation.Data.unwrap())
                                {
                                    string_ids.push(date.PromptStringId);
                                    string_ids.push(date.HelpStringId);
                                }
                            }
                            framework_parser::IfrOpcode::Time => {
                                if let Ok((_, time)) =
                                    framework_parser::ifr_time(operation.Data.unwrap())
                                {
                                    string_ids.push(time.PromptStringId);
                                    string_ids.push(time.HelpStringId);
                                }
                            }
                            framework_parser::IfrOpcode::String => {
                                if let Ok((_, str)) =
                                    framework_parser::ifr_string(operation.Data.unwrap())
                                {
                                    string_ids.push(str.PromptStringId);
                                    string_ids.push(str.HelpStringId);
                                }
                            }
                            framework_parser::IfrOpcode::Label => {}
                            framework_parser::IfrOpcode::SaveDefaults => {
                                if let Ok((_, sd)) =
                                    framework_parser::ifr_save_defaults(operation.Data.unwrap())
                                {
                                    string_ids.push(sd.PromptStringId);
                                    string_ids.push(sd.HelpStringId);
                                }
                            }
                            framework_parser::IfrOpcode::RestoreDefaults => {
                                if let Ok((_, rd)) =
                                    framework_parser::ifr_restore_defaults(operation.Data.unwrap())
                                {
                                    string_ids.push(rd.PromptStringId);
                                    string_ids.push(rd.HelpStringId);
                                }
                            }
                            framework_parser::IfrOpcode::Banner => {
                                if let Ok((_, banner)) =
                                    framework_parser::ifr_banner(operation.Data.unwrap())
                                {
                                    string_ids.push(banner.TitleStringId);
                                }
                            }
                            framework_parser::IfrOpcode::Inventory => {
                                if let Ok((_, inv)) =
                                    framework_parser::ifr_inventory(operation.Data.unwrap())
                                {
                                    string_ids.push(inv.HelpStringId);
                                    string_ids.push(inv.TextStringId);
                                    string_ids.push(inv.TextTwoStringId);
                                }
                            }
                            framework_parser::IfrOpcode::EqVarVal => {}
                            framework_parser::IfrOpcode::OrderedList => {
                                if let Ok((_, ol)) =
                                    framework_parser::ifr_ordered_list(operation.Data.unwrap())
                                {
                                    string_ids.push(ol.PromptStringId);
                                    string_ids.push(ol.HelpStringId);
                                }
                            }
                            framework_parser::IfrOpcode::VarStore => {}
                            framework_parser::IfrOpcode::VarStoreSelect => {}
                            framework_parser::IfrOpcode::VarStoreSelectPair => {}
                            framework_parser::IfrOpcode::True => {}
                            framework_parser::IfrOpcode::False => {}
                            framework_parser::IfrOpcode::Greater => {}
                            framework_parser::IfrOpcode::GreaterEqual => {}
                            framework_parser::IfrOpcode::OemDefined => {}
                            framework_parser::IfrOpcode::Oem => {}
                            framework_parser::IfrOpcode::NvAccessCommand => {}
                            framework_parser::IfrOpcode::Unknown(_) => {}
                        }
                    }
                }

                // Find min and max StringId, and the number of unique ones
                string_ids.sort();
                string_ids.dedup();
                if string_ids.len() > 0 {
                    // Add the required information to forms
                    let form = (
                        i,
                        candidate.len(),
                        string_ids.len(),
                        *string_ids.first().unwrap(),
                        *string_ids.last().unwrap(),
                    );
                    forms.push(form);
                }

                i += candidate.len();
            } else {
                i += 1;
            }
        } else {
            i += 1;
        }
    }

    // No need to continue if no forms are found
    if forms.len() == 0 {
        return (Vec::new(), Vec::new());
    }

    // Construct return value
    let mut result_strings = Vec::new();
    let mut result_forms = Vec::new();
    for string in &strings {
        result_strings.push(StringPackage {
            offset: string.0,
            length: string.1,
            language: string.2.clone(),
            string_id_map: string.3.clone(),
        });
    }
    for form in &forms {
        result_forms.push(FormPackage {
            offset: form.0,
            length: form.1,
            used_strings: form.2,
            min_string_id: form.3,
            max_string_id: form.4,
        });
    }

    return (result_strings, result_forms);
}

fn framework_ifr_extract(
    path: &OsStr,
    data: &[u8],
    form_package: &FormPackage,
    form_package_index: usize,
    string_package: &StringPackage,
    string_package_index: usize,
    verbose_mode: bool,
) -> () {
    let mut text = Vec::new();
    let strings_map = &string_package.string_id_map;

    if let Ok((_, candidate)) =
        framework_parser::hii_form_package_candidate(&data[form_package.offset..])
    {
        if let Ok((_, package)) = framework_parser::hii_package(candidate) {
            // Parse form package and output its structure as human-readable strings
            match framework_parser::ifr_operations(package.Data.unwrap()) {
                Ok((_, operations)) => {
                    let mut scope_depth = 0;
                    let mut current_operation_offset = form_package.offset + 6; // Header size of Framework HII form package is 6 bytes
                    for operation in &operations {
                        // Special case of operations that decrease scope_depth
                        if operation.OpCode == framework_parser::IfrOpcode::EndFormSet
                            || operation.OpCode == framework_parser::IfrOpcode::EndForm
                        {
                            if scope_depth > 0 {
                                scope_depth -= 1;
                            }
                        }

                        if verbose_mode {
                            write!(
                                &mut text,
                                "0x{:X}: ",
                                current_operation_offset
                            )
                            .unwrap();
                        }

                        write!(
                            &mut text,
                            "{:\t<1$}{2:?} ",
                            "", scope_depth, operation.OpCode
                        )
                        .unwrap();

                        match operation.OpCode {
                            //0x01: Form
                            framework_parser::IfrOpcode::Form => {
                                match framework_parser::ifr_form(operation.Data.unwrap()) {
                                    Ok((_, form)) => {
                                        write!(
                                            &mut text,
                                            "Title: \"{}\", FormId: 0x{:X}",
                                            strings_map
                                                .get(&form.TitleStringId)
                                                .unwrap_or(&String::from("InvalidId")),
                                            form.FormId
                                        )
                                        .unwrap();
                                    }
                                    Err(e) => {
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("Form parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }

                                scope_depth += 1;
                            }
                            //0x02: Subtitle
                            framework_parser::IfrOpcode::Subtitle => {
                                match framework_parser::ifr_subtitle(operation.Data.unwrap()) {
                                    Ok((_, subtitle)) => {
                                        write!(
                                            &mut text,
                                            "Subtitle: \"{}\"",
                                            strings_map
                                                .get(&subtitle.SubtitleStringId)
                                                .unwrap_or(&String::from("InvalidId"))
                                        )
                                        .unwrap();
                                    }
                                    Err(e) => {
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("Subtitle parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            //0x03: Text
                            framework_parser::IfrOpcode::Text => {
                                match framework_parser::ifr_text(operation.Data.unwrap()) {
                                    Ok((_, txt)) => {
                                        write!(&mut text,
                                            "Text: \"{}\", TextTwo: \"{}\", Help: \"{}\", Flags: 0x{:X}, Key: 0x{:X}",
                                            strings_map.get(&txt.TextStringId).unwrap_or(&String::from("InvalidId")),
                                            strings_map.get(&txt.TextTwoStringId).unwrap_or(&String::from("InvalidId")),
                                            strings_map.get(&txt.HelpStringId).unwrap_or(&String::from("InvalidId")),
                                            txt.Flags,
                                            txt.Key
                                        ).unwrap();
                                    }
                                    Err(e) => {
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("Text parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            //0x04: Graphic, should be unused
                            framework_parser::IfrOpcode::Graphic => {}
                            //0x05: OneOf
                            framework_parser::IfrOpcode::OneOf => {
                                match framework_parser::ifr_one_of(operation.Data.unwrap()) {
                                    Ok((_, oneof)) => {
                                        write!(
                                            &mut text,
                                            "Prompt: \"{}\", Help: \"{}\", QuestionId: 0x{:X}, Width: 0x{:X}",
                                            strings_map
                                                .get(&oneof.PromptStringId)
                                                .unwrap_or(&String::from("InvalidId")),
                                            strings_map
                                                .get(&oneof.HelpStringId)
                                                .unwrap_or(&String::from("InvalidId")),
                                            oneof.QuestionId,
                                            oneof.Width
                                        )
                                        .unwrap();
                                    }
                                    Err(e) => {
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("OneOf parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            //0x06: CheckBox
                            framework_parser::IfrOpcode::CheckBox => {
                                match framework_parser::ifr_check_box(operation.Data.unwrap()) {
                                    Ok((_, checkbox)) => {
                                        write!(&mut text,
                                            "Prompt: \"{}\", Help: \"{}\", QuestionId: 0x{:X}, Width: 0x{:X}, Flags: 0x{:X}, Key: 0x{:X}",
                                            strings_map.get(&checkbox.PromptStringId).unwrap_or(&String::from("InvalidId")),
                                            strings_map.get(&checkbox.HelpStringId).unwrap_or(&String::from("InvalidId")),
                                            checkbox.QuestionId,
                                            checkbox.Width,
                                            checkbox.Flags,
                                            checkbox.Key
                                        ).unwrap();
                                    }
                                    Err(e) => {
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("CheckBox parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            //0x07: Numeric
                            framework_parser::IfrOpcode::Numeric => {
                                match framework_parser::ifr_numeric(operation.Data.unwrap()) {
                                    Ok((_, numeric)) => {
                                        write!(&mut text,
                                            "Prompt: \"{}\", Help: \"{}\", QuestionId: 0x{:X}, Width: 0x{:X}, Flags: 0x{:X}, Key: 0x{:X}, Min: 0x{:X}, Max: 0x{:X}, Step: 0x{:X}, Default: 0x{:X}",
                                            strings_map.get(&numeric.PromptStringId).unwrap_or(&String::from("InvalidId")),
                                            strings_map.get(&numeric.HelpStringId).unwrap_or(&String::from("InvalidId")),
                                            numeric.QuestionId,
                                            numeric.Width,
                                            numeric.Flags,
                                            numeric.Key,
                                            numeric.Min,
                                            numeric.Max,
                                            numeric.Step,
                                            numeric.Default
                                        ).unwrap();
                                    }
                                    Err(e) => {
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("Numeric parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            //0x08: Password
                            framework_parser::IfrOpcode::Password => {
                                match framework_parser::ifr_password(operation.Data.unwrap()) {
                                    Ok((_, password)) => {
                                        write!(&mut text,
                                            "Prompt: \"{}\", Help: \"{}\", QuestionId: 0x{:X}, Width: 0x{:X}, Flags: 0x{:X}, Key: 0x{:X}, MinSize: 0x{:X}, MaxSize: 0x{:X}, Encoding 0x{:X}",
                                            strings_map.get(&password.PromptStringId).unwrap_or(&String::from("InvalidId")),
                                            strings_map.get(&password.HelpStringId).unwrap_or(&String::from("InvalidId")),
                                            password.QuestionId,
                                            password.Width,
                                            password.Flags,
                                            password.Key,
                                            password.MinSize,
                                            password.MaxSize,
                                            password.Encoding
                                        ).unwrap();
                                    }
                                    Err(e) => {
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("Password parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            //0x09: OneOfOption
                            framework_parser::IfrOpcode::OneOfOption => {
                                match framework_parser::ifr_one_of_option(operation.Data.unwrap()) {
                                    Ok((_, oneofopt)) => {
                                        write!(
                                            &mut text,
                                            "Option: \"{}\", Value: 0x{:X}, Flags: 0x{:X}, Key: 0x{:X}",
                                            strings_map
                                                .get(&oneofopt.OptionStringId)
                                                .unwrap_or(&String::from("InvalidId")),
                                            oneofopt.Value,
                                            oneofopt.Flags,
                                            oneofopt.Key
                                        )
                                        .unwrap();
                                    }
                                    Err(e) => {
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("OneOfOption parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            //0x0A: SuppressIf
                            framework_parser::IfrOpcode::SuppressIf => {
                                match framework_parser::ifr_supress_if(operation.Data.unwrap()) {
                                    Ok((_, supressif)) => {
                                        write!(&mut text, "Flags: 0x{:X}", supressif.Flags)
                                            .unwrap();
                                    }
                                    Err(e) => {
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("SupressIf parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            //0x0B: EndForm
                            framework_parser::IfrOpcode::EndForm => {}
                            //0x0C: Hidden
                            framework_parser::IfrOpcode::Hidden => {
                                match framework_parser::ifr_hidden(operation.Data.unwrap()) {
                                    Ok((_, hidden)) => {
                                        write!(
                                            &mut text,
                                            "Value: 0x{:X}, Key: 0x{:X}",
                                            hidden.Value, hidden.Key
                                        )
                                        .unwrap();
                                    }
                                    Err(e) => {
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("Hidden parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            //0x0D: EndFormSet
                            framework_parser::IfrOpcode::EndFormSet => {}
                            //0x0E: FormSet
                            framework_parser::IfrOpcode::FormSet => {
                                match framework_parser::ifr_form_set(operation.Data.unwrap()) {
                                    Ok((_, formset)) => {
                                        write!(&mut text,
                                            "Title: \"{}\", Help: \"{}\", Guid: {}, CallbackHandle: 0x{:X}, Class: 0x{:X}, SubClass: 0x{:X}, NvDataSize: 0x{:X}",
                                            strings_map.get(&formset.TitleStringId).unwrap_or(&String::from("InvalidId")),
                                            strings_map.get(&formset.HelpStringId).unwrap_or(&String::from("InvalidId")),
                                            formset.Guid,
                                            formset.CallbackHandle,
                                            formset.Class,
                                            formset.SubClass,
                                            formset.NvDataSize
                                        ).unwrap();
                                    }
                                    Err(e) => {
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("FromSet parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }

                                scope_depth += 1;
                            }
                            //0x0F: Ref
                            framework_parser::IfrOpcode::Ref => {
                                match framework_parser::ifr_ref(operation.Data.unwrap()) {
                                    Ok((_, rf)) => {
                                        write!(&mut text,
                                            "Prompt: \"{}\", Help: \"{}\", FormId: 0x{:X}, Flags: 0x{:X}, Key: 0x{:X}",
                                            strings_map.get(&rf.PromptStringId).unwrap_or(&String::from("InvalidId")),
                                            strings_map.get(&rf.HelpStringId).unwrap_or(&String::from("InvalidId")),
                                            rf.FormId,
                                            rf.Flags,
                                            rf.Key
                                        ).unwrap();
                                    }
                                    Err(e) => {
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("Ref parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            //0x10: End
                            framework_parser::IfrOpcode::End => {}
                            //0x11: InconsistentIf
                            framework_parser::IfrOpcode::InconsistentIf => {
                                match framework_parser::ifr_inconsistent_if(operation.Data.unwrap())
                                {
                                    Ok((_, incif)) => {
                                        write!(
                                            &mut text,
                                            "Popup: \"{}\", Flags: 0x{:X}",
                                            strings_map
                                                .get(&incif.PopupStringId)
                                                .unwrap_or(&String::from("InvalidId")),
                                            incif.Flags
                                        )
                                        .unwrap();
                                    }
                                    Err(e) => {
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("InconsistentIf parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            //0x12: EqIdVal
                            framework_parser::IfrOpcode::EqIdVal => {
                                match framework_parser::ifr_eq_id_val(operation.Data.unwrap()) {
                                    Ok((_, eqidval)) => {
                                        write!(
                                            &mut text,
                                            "QuestionId: 0x{:X}, Value: 0x{:X}",
                                            eqidval.QuestionId, eqidval.Value
                                        )
                                        .unwrap();
                                    }
                                    Err(e) => {
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("EqIdVal parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            //0x13: EqIdId
                            framework_parser::IfrOpcode::EqIdId => {
                                match framework_parser::ifr_eq_id_id(operation.Data.unwrap()) {
                                    Ok((_, eqidid)) => {
                                        write!(
                                            &mut text,
                                            "QuestionId1: 0x{:X}, QuestionId2: 0x{:X}",
                                            eqidid.QuestionId1, eqidid.QuestionId2
                                        )
                                        .unwrap();
                                    }
                                    Err(e) => {
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("EqIdId parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            //0x14: EqIdList
                            framework_parser::IfrOpcode::EqIdList => {
                                match framework_parser::ifr_eq_id_list(operation.Data.unwrap()) {
                                    Ok((_, eqidlist)) => {
                                        write!(
                                            &mut text,
                                            "QuestionId: 0x{:X}, Width: 0x{:X}, List: {{",
                                            eqidlist.QuestionId, eqidlist.Width
                                        )
                                        .unwrap();
                                        for item in &eqidlist.List {
                                            write!(&mut text, " 0x{:X},", *item).unwrap();
                                        }
                                        write!(&mut text, " }}").unwrap();
                                    }
                                    Err(e) => {
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("EqIdList parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            //0x15: And
                            framework_parser::IfrOpcode::And => {}
                            //0x16: Or
                            framework_parser::IfrOpcode::Or => {}
                            //0x17: Not
                            framework_parser::IfrOpcode::Not => {}
                            //0x18: EndIf
                            framework_parser::IfrOpcode::EndIf => {}
                            //0x19: GrayOutIf
                            framework_parser::IfrOpcode::GrayOutIf => {
                                match framework_parser::ifr_grayout_if(operation.Data.unwrap()) {
                                    Ok((_, grif)) => {
                                        write!(&mut text, "Flags: 0x{:X}", grif.Flags).unwrap();
                                    }
                                    Err(e) => {
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("GrayoutIf parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            //0x1A: Date
                            framework_parser::IfrOpcode::Date => {
                                match framework_parser::ifr_date(operation.Data.unwrap()) {
                                    Ok((_, date)) => {
                                        write!(&mut text,
                                            "Prompt: \"{}\", Help: \"{}\", QuestionId: 0x{:X}, Width: 0x{:X}, Flags: 0x{:X}, Key: 0x{:X}, Min: 0x{:X}, Max: 0x{:X}, Step: 0x{:X}, Default: 0x{:X}",
                                            strings_map.get(&date.PromptStringId).unwrap_or(&String::from("InvalidId")),
                                            strings_map.get(&date.HelpStringId).unwrap_or(&String::from("InvalidId")),
                                            date.QuestionId,
                                            date.Width,
                                            date.Flags,
                                            date.Key,
                                            date.Min,
                                            date.Max,
                                            date.Step,
                                            date.Default
                                        ).unwrap();
                                    }
                                    Err(e) => {
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("Date parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            //0x1B: Time
                            framework_parser::IfrOpcode::Time => {
                                match framework_parser::ifr_time(operation.Data.unwrap()) {
                                    Ok((_, time)) => {
                                        write!(&mut text,
                                            "Prompt: \"{}\", Help: \"{}\", QuestionId: 0x{:X}, Width: 0x{:X}, Flags: 0x{:X}, Key: 0x{:X}, Min: 0x{:X}, Max: 0x{:X}, Step: 0x{:X}, Default: 0x{:X}",
                                            strings_map.get(&time.PromptStringId).unwrap_or(&String::from("InvalidId")),
                                            strings_map.get(&time.HelpStringId).unwrap_or(&String::from("InvalidId")),
                                            time.QuestionId,
                                            time.Width,
                                            time.Flags,
                                            time.Key,
                                            time.Min,
                                            time.Max,
                                            time.Step,
                                            time.Default
                                        ).unwrap();
                                    }
                                    Err(e) => {
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("Time parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            //0x1C: String
                            framework_parser::IfrOpcode::String => {
                                match framework_parser::ifr_string(operation.Data.unwrap()) {
                                    Ok((_, str)) => {
                                        write!(&mut text,
                                            "Prompt: \"{}\", Help: \"{}\", QuestionId: 0x{:X}, Width: 0x{:X}, Flags: 0x{:X}, Key: 0x{:X}, MinSize: 0x{:X}, MaxSize: 0x{:X}",
                                            strings_map.get(&str.PromptStringId).unwrap_or(&String::from("InvalidId")),
                                            strings_map.get(&str.HelpStringId).unwrap_or(&String::from("InvalidId")),
                                            str.QuestionId,
                                            str.Width,
                                            str.Flags,
                                            str.Key,
                                            str.MinSize,
                                            str.MaxSize
                                        ).unwrap();
                                    }
                                    Err(e) => {
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("String parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            //0x1D: Label
                            framework_parser::IfrOpcode::Label => {
                                match framework_parser::ifr_label(operation.Data.unwrap()) {
                                    Ok((_, label)) => {
                                        write!(&mut text, "LabelId: 0x{:X}", label.LabelId)
                                            .unwrap();
                                    }
                                    Err(e) => {
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("Label parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            //0x1E: SaveDefaults
                            framework_parser::IfrOpcode::SaveDefaults => {
                                match framework_parser::ifr_save_defaults(operation.Data.unwrap()) {
                                    Ok((_, sd)) => {
                                        write!(&mut text,
                                            "Prompt: \"{}\", Help: \"{}\", FormId: 0x{:X}, Flags: 0x{:X}, Key: 0x{:X}",
                                            strings_map.get(&sd.PromptStringId).unwrap_or(&String::from("InvalidId")),
                                            strings_map.get(&sd.HelpStringId).unwrap_or(&String::from("InvalidId")),
                                            sd.FormId,
                                            sd.Flags,
                                            sd.Key
                                        ).unwrap();
                                    }
                                    Err(e) => {
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("SaveDefaults parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            //0x1F: RestoreDefaults
                            framework_parser::IfrOpcode::RestoreDefaults => {
                                match framework_parser::ifr_restore_defaults(
                                    operation.Data.unwrap(),
                                ) {
                                    Ok((_, rd)) => {
                                        write!(&mut text,
                                            "Prompt: \"{}\", Help: \"{}\", FormId: 0x{:X}, Flags: 0x{:X}, Key: 0x{:X}",
                                            strings_map.get(&rd.PromptStringId).unwrap_or(&String::from("InvalidId")),
                                            strings_map.get(&rd.HelpStringId).unwrap_or(&String::from("InvalidId")),
                                            rd.FormId,
                                            rd.Flags,
                                            rd.Key
                                        ).unwrap();
                                    }
                                    Err(e) => {
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("RestoreDefaults parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            //0x20: Banner
                            framework_parser::IfrOpcode::Banner => {
                                match framework_parser::ifr_banner(operation.Data.unwrap()) {
                                    Ok((_, banner)) => {
                                        write!(
                                            &mut text,
                                            "Title: \"{}\", LineNumber: 0x{:X}, Alignment: 0x{:X}",
                                            strings_map
                                                .get(&banner.TitleStringId)
                                                .unwrap_or(&String::from("InvalidId")),
                                            banner.LineNumber,
                                            banner.Alignment
                                        )
                                        .unwrap();
                                    }
                                    Err(e) => {
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("Banner parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            //0x21: Inventory
                            framework_parser::IfrOpcode::Inventory => {
                                match framework_parser::ifr_inventory(operation.Data.unwrap()) {
                                    Ok((_, inventory)) => {
                                        write!(
                                            &mut text,
                                            "Text: \"{}\", TextTwo: \"{}\", Help: \"{}\"",
                                            strings_map
                                                .get(&inventory.TextStringId)
                                                .unwrap_or(&String::from("InvalidId")),
                                            strings_map
                                                .get(&inventory.TextTwoStringId)
                                                .unwrap_or(&String::from("InvalidId")),
                                            strings_map
                                                .get(&inventory.HelpStringId)
                                                .unwrap_or(&String::from("InvalidId"))
                                        )
                                        .unwrap();
                                    }
                                    Err(e) => {
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("Inventory parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            //0x22: EqVarVal
                            framework_parser::IfrOpcode::EqVarVal => {
                                match framework_parser::ifr_eq_var_val(operation.Data.unwrap()) {
                                    Ok((_, eqvarval)) => {
                                        write!(
                                            &mut text,
                                            "VariableId: 0x{:X}, Value: 0x{:X}",
                                            eqvarval.VariableId, eqvarval.Value
                                        )
                                        .unwrap();
                                    }
                                    Err(e) => {
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("EqVarVal parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            //0x23: OrderedList
                            framework_parser::IfrOpcode::OrderedList => {
                                match framework_parser::ifr_ordered_list(operation.Data.unwrap()) {
                                    Ok((_, ol)) => {
                                        write!(&mut text,
                                            "Prompt: \"{}\", Help: \"{}\", QuestionId: 0x{:X}, MaxEntries: 0x{:X}",
                                            strings_map.get(&ol.PromptStringId).unwrap_or(&String::from("InvalidId")),
                                            strings_map.get(&ol.HelpStringId).unwrap_or(&String::from("InvalidId")),
                                            ol.QuestionId,
                                            ol.MaxEntries
                                        ).unwrap();
                                    }
                                    Err(e) => {
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("OrderedList parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            //0x24: VarStore
                            framework_parser::IfrOpcode::VarStore => {
                                match framework_parser::ifr_var_store(operation.Data.unwrap()) {
                                    Ok((_, vs)) => {
                                        write!(
                                            &mut text,
                                            "VarstoreId: 0x{:X}, Guid: {}, Name: \"{}\", Size: 0x{:X}",
                                            vs.VarStoreId, vs.Guid, vs.Name, vs.Size
                                        )
                                        .unwrap();
                                    }
                                    Err(e) => {
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("VarStore parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            //0x25: VarStoreSelect
                            framework_parser::IfrOpcode::VarStoreSelect => {
                                match framework_parser::ifr_var_store_select(
                                    operation.Data.unwrap(),
                                ) {
                                    Ok((_, vss)) => {
                                        write!(&mut text, "VarstoreId: 0x{:X}", vss.VarStoreId)
                                            .unwrap();
                                    }
                                    Err(e) => {
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("VarStoreSelect parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            //0x26: VarStoreSelectPair
                            framework_parser::IfrOpcode::VarStoreSelectPair => {
                                match framework_parser::ifr_var_store_select_pair(
                                    operation.Data.unwrap(),
                                ) {
                                    Ok((_, vssp)) => {
                                        write!(
                                            &mut text,
                                            "VarstoreId: 0x{:X}, SecondaryVarStoreId: 0x{:X}",
                                            vssp.VarStoreId, vssp.SecondaryVarStoreId
                                        )
                                        .unwrap();
                                    }
                                    Err(e) => {
                                        write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                            .unwrap();
                                        println!("VarStoreSelectPair parse error: {:?} at offset 0x{:X}", e, current_operation_offset);
                                    }
                                }
                            }
                            //0x27: True
                            framework_parser::IfrOpcode::True => {}
                            //0x28: False
                            framework_parser::IfrOpcode::False => {}
                            //0x29: Greater
                            framework_parser::IfrOpcode::Greater => {}
                            //0x2A: GreaterEqual
                            framework_parser::IfrOpcode::GreaterEqual => {}
                            //0x2B: OemDefined
                            framework_parser::IfrOpcode::OemDefined => {}
                            //0xFE: Oem
                            framework_parser::IfrOpcode::Oem => {}
                            //0xFF: NvAccessCommand
                            framework_parser::IfrOpcode::NvAccessCommand => {}
                            //Unknown operation
                            framework_parser::IfrOpcode::Unknown(x) => {
                                write!(&mut text, "RawData: {:02X?}", operation.Data.unwrap())
                                    .unwrap();
                                println!("IFR operation of unknown type 0x{:X}", x);
                            }
                        }
                        current_operation_offset += operation.Length as usize;
                        
                        if verbose_mode {
                            write!(&mut text, " {}", operation).unwrap();
                        }

                        writeln!(&mut text, "").unwrap();
                    }
                }
                Err(e) => {
                    println!("IFR operations parse error: {:?}", e);
                }
            }
        }
    }

    // Write the result
    let mut file_path = OsString::new();
    file_path.push(path);
    file_path.push(".");
    file_path.push(form_package_index.to_string());
    file_path.push(".");
    file_path.push(string_package_index.to_string());
    file_path.push(".");
    file_path.push(string_package.language.clone());
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

fn main() {
    // Obtain program arguments
    let mut args = std::env::args_os();

    // Check if we have none
    if args.len() <= 1 {
        println!("
IFRExtractor RS v{} - extracts HII string and form packages in UEFI Internal Form Representation (IFR) from a binary file into human-readable text
Usage: ifrextractor file.bin list - list all string and form packages in the input file
       ifrextractor file.bin single <form_package_number> <string_package_number> - extract a given form package using a given string package (use list command to obtain the package numbers)
       ifrextractor file.bin lang <language> - extract all form packages using all string packages in a given language      
       ifrextractor file.bin all - extract all form package using all string packages
       ifrextractor file.bin verbose - extract all form packages using string packages in English, add raw bytes to all opcodes
       ifrextractor file.bin - default extraction mode (only try string packages in English)", 
        VERSION.unwrap_or("0.0.0"));
        std::process::exit(1);
    }

    // The only mandatory argument is a path to input file
    let arg = args.nth(1).expect("Failed to obtain file path");
    let path = Path::new(&arg);

    // Open input file
    let mut file = File::open(&path).expect("Can't open input file");

    // Read the whole file as binary data
    let mut data = Vec::new();
    file.read_to_end(&mut data).expect("Can't read input file");

    // Find all string and form packages in UEFI HII format
    let mut uefi_ifr_found = true;
    let (uefi_strings, uefi_forms) = uefi_find_string_and_form_packages(&data);
    if uefi_strings.is_empty() || uefi_forms.is_empty() {
        uefi_ifr_found = false;
    }

    // Find all string and form packages in Framework HII format
    let mut framework_ifr_found = true;
    let (framework_strings, framework_forms) = framework_find_string_and_form_packages(&data);
    if framework_strings.is_empty() || framework_forms.is_empty() {
        framework_ifr_found = false;
    }

    // Exit early if nothing is found
    if !uefi_ifr_found && !framework_ifr_found {
        println!("No IFR data found");
        std::process::exit(2);
    }

    // Parse the other arguments
    let collected_args: Vec<String> = env::args().collect();
    if collected_args.len() == 2 {
        // Extract all form packages using all string packages with english language
        if uefi_ifr_found {
            println!("Extracting all UEFI HII form packages using en-US UEFI HII string packages");
            let mut found = false;
            let mut form_num = 0;
            for form in &uefi_forms {
                let mut string_num = 0;
                for string in &uefi_strings {
                    if string.language == "en-US" {
                        found = true;
                        uefi_ifr_extract(
                            path.as_os_str(),
                            &data,
                            form,
                            form_num,
                            string,
                            string_num,
                            false
                        );
                    }
                    string_num += 1;
                }
                form_num += 1;
            }
            if !found {
                println!("No en-US UEFI HII string packages found");
                std::process::exit(2);
            }
        } else if framework_ifr_found {
            println!("Extracting all Framework HII form packages using eng Framework HII string packages");
            let mut found = false;
            let mut form_num = 0;
            for form in &framework_forms {
                let mut string_num = 0;
                for string in &framework_strings {
                    if string.language == "eng" {
                        found = true;
                        framework_ifr_extract(
                            path.as_os_str(),
                            &data,
                            form,
                            form_num,
                            string,
                            string_num,
                            false
                        );
                    }
                    string_num += 1;
                }
                form_num += 1;
            }
            if !found {
                println!("No eng Framework HII string packages found");
                std::process::exit(2);
            }
        }
    } else if collected_args.len() == 3 && collected_args[2] == "verbose" {
        // Extract all form packages using all string packages with english language in verbose mode
        if uefi_ifr_found {
            println!("Extracting all UEFI HII form packages using en-US UEFI HII string packages in verbose mode");
            let mut found = false;
            let mut form_num = 0;
            for form in &uefi_forms {
                let mut string_num = 0;
                for string in &uefi_strings {
                    if string.language == "en-US" {
                        found = true;
                        uefi_ifr_extract(
                            path.as_os_str(),
                            &data,
                            form,
                            form_num,
                            string,
                            string_num,
                            true
                        );
                    }
                    string_num += 1;
                }
                form_num += 1;
            }
            if !found {
                println!("No en-US UEFI HII string packages found");
                std::process::exit(2);
            }
        } else if framework_ifr_found {
            println!("Extracting all Framework HII form packages using eng Framework HII string packages in vebose mode");
            let mut found = false;
            let mut form_num = 0;
            for form in &framework_forms {
                let mut string_num = 0;
                for string in &framework_strings {
                    if string.language == "eng" {
                        found = true;
                        framework_ifr_extract(
                            path.as_os_str(),
                            &data,
                            form,
                            form_num,
                            string,
                            string_num,
                            true
                        );
                    }
                    string_num += 1;
                }
                form_num += 1;
            }
            if !found {
                println!("No eng Framework HII string packages found");
                std::process::exit(2);
            }
        }
    } else if collected_args.len() == 3 && collected_args[2] == "list" {
        if uefi_ifr_found {
            println!("UEFI HII form packages:");
            let mut num = 0;
            for form in &uefi_forms {
                println!("Index: {}, Offset: 0x{:X}, Length: 0x{:X}, Used strings: {}, Min StringId: 0x{:X}, Max StringId: 0x{:X}",
                        num, form.offset, form.length, form.used_strings, form.min_string_id, form.max_string_id);
                num += 1;
            }
            println!("UEFI HII string packages:");
            num = 0;
            for string in &uefi_strings {
                println!(
                    "Index: {}, Offset: 0x{:X}, Length: 0x{:X}, Language: {}, Total strings: {}",
                    num,
                    string.offset,
                    string.length,
                    string.language,
                    string.string_id_map.len()
                );
                num += 1;
            }
        } else if framework_ifr_found {
            println!("Framework HII form packages:");
            let mut num = 0;
            for form in &framework_forms {
                println!("Index: {}, Offset: 0x{:X}, Length: 0x{:X}, Used strings: {}, Min StringId: 0x{:X}, Max StringId: 0x{:X}",
                        num, form.offset, form.length, form.used_strings, form.min_string_id, form.max_string_id);
                num += 1;
            }
            println!("Framework HII string packages:");
            num = 0;
            for string in &framework_strings {
                println!(
                    "Index: {}, Offset: 0x{:X}, Length: 0x{:X}, Language: {}, Total strings: {}",
                    num,
                    string.offset,
                    string.length,
                    string.language,
                    string.string_id_map.len()
                );
                num += 1;
            }
        }
    } else if collected_args.len() == 3 && collected_args[2] == "all" {
        if uefi_ifr_found {
            println!("Extracting all UEFI HII form packages using all UEFI HII string packages");
            let mut form_num = 0;
            for form in &uefi_forms {
                let mut string_num = 0;
                for string in &uefi_strings {
                    uefi_ifr_extract(path.as_os_str(), &data, form, form_num, string, string_num, false);
                    string_num += 1;
                }
                form_num += 1;
            }
        } else if framework_ifr_found {
            println!("Extracting all Framework HII form packages using all Framework HII string packages");
            let mut form_num = 0;
            for form in &framework_forms {
                let mut string_num = 0;
                for string in &framework_strings {
                    framework_ifr_extract(
                        path.as_os_str(),
                        &data,
                        form,
                        form_num,
                        string,
                        string_num,
                        false
                    );
                    string_num += 1;
                }
                form_num += 1;
            }
        }
    } else if collected_args.len() == 4 && collected_args[2] == "lang" {
        // Extract all form packages using all string packages in a given language
        if uefi_ifr_found {
            println!(
                "Extracting all UEFI HII form packages using {} string packages",
                collected_args[3]
            );
            let mut found = false;
            let mut form_num = 0;
            for form in &uefi_forms {
                let mut string_num = 0;
                for string in &uefi_strings {
                    if string.language == collected_args[3] {
                        found = true;
                        uefi_ifr_extract(
                            path.as_os_str(),
                            &data,
                            form,
                            form_num,
                            string,
                            string_num,
                            false
                        );
                    }
                    string_num += 1;
                }
                form_num += 1;
            }
            if !found {
                println!("No {} UEFI HII string packages found", collected_args[3]);
                std::process::exit(2);
            }
        } else if framework_ifr_found {
            println!(
                "Extracting all Framework HII form packages using {} Framework HII string packages",
                collected_args[3]
            );
            let mut found = false;
            let mut form_num = 0;
            for form in &framework_forms {
                let mut string_num = 0;
                for string in &framework_strings {
                    if string.language == collected_args[3] {
                        found = true;
                        framework_ifr_extract(
                            path.as_os_str(),
                            &data,
                            form,
                            form_num,
                            string,
                            string_num,
                            false
                        );
                    }
                    string_num += 1;
                }
                form_num += 1;
            }
            if !found {
                println!(
                    "No {} Framework HII string packages found",
                    collected_args[3]
                );
                std::process::exit(2);
            }
        }
    } else if collected_args.len() == 5 && collected_args[2] == "single" {
        if uefi_ifr_found {
            // Extract the exact single combination
            let form_package_num: usize = collected_args[3]
                .parse()
                .expect("Can't parse form_package_number argument as a number");
            if form_package_num > uefi_forms.len() - 1 {
                println!(
                    "Provided form_package_number argument {} is out of range [0..{}]",
                    form_package_num,
                    uefi_forms.len() - 1
                );
                std::process::exit(4);
            }
            let string_package_num: usize = collected_args[4]
                .parse()
                .expect("Can't parse string_package_number argument as a number");
            if string_package_num > uefi_strings.len() - 1 {
                println!(
                    "Provided string_package_number argument {} is out of range [0..{}]",
                    string_package_num,
                    uefi_strings.len() - 1
                );
                std::process::exit(4);
            }
            println!(
                "Extracting UEFI HII form package #{} using UEFI HII string package #{}",
                form_package_num, string_package_num
            );
            uefi_ifr_extract(
                path.as_os_str(),
                &data,
                &uefi_forms[form_package_num],
                form_package_num,
                &uefi_strings[string_package_num],
                string_package_num,
                false
            );
        } else if framework_ifr_found {
            let form_package_num: usize = collected_args[3]
                .parse()
                .expect("Can't parse form_package_number argument as a number");
            if form_package_num > framework_forms.len() - 1 {
                println!(
                    "Provided form_package_number argument {} is out of range [0..{}]",
                    form_package_num,
                    uefi_forms.len() - 1
                );
                std::process::exit(4);
            }
            let string_package_num: usize = collected_args[4]
                .parse()
                .expect("Can't parse string_package_number argument as a number");
            if string_package_num > framework_strings.len() - 1 {
                println!(
                    "Provided string_package_number argument {} is out of range [0..{}]",
                    string_package_num,
                    uefi_strings.len() - 1
                );
                std::process::exit(4);
            }
            println!(
                "Extracting Framework HII form package #{} using Framework HII string package #{}",
                form_package_num, string_package_num
            );
            framework_ifr_extract(
                path.as_os_str(),
                &data,
                &framework_forms[form_package_num],
                form_package_num,
                &framework_strings[string_package_num],
                string_package_num,
                false
            );
        }
    } else {
        println!("Invalid arguments");
        std::process::exit(4);
    }
}
