// Parser
#[macro_use]
extern crate nom;
pub mod parser;

// Main
use std::collections::HashMap;
use std::fs::File;
use std::fs::OpenOptions;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::io::prelude::*;
use std::io::Write;
use std::path::Path;

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

    // Call extraction function
    ifr_extract(path.as_os_str(), &data);
}

fn ifr_extract(path: &OsStr, data: &[u8]) -> () {
    let mut text = Vec::new(); // Output text
    let mut strings_map = HashMap::new(); // Map of StringIds to strings

    //
    // Search for all string packages in the input file 
    // to build an ID to string map
    //
    // Usage a C-style loop here is ugly, but works fine enough
    // TODO: refactor later
    let mut i = 0;
    while i < data.len() {
        if let Ok((_, candidate)) = parser::hii_string_package_candidate(&data[i..]) {
            if let Ok((_, package)) = parser::hii_package(candidate) {
                if let Ok((unp, string_package)) = parser::hii_string_package(package.Data.unwrap()) {
                    if unp.len() > 0 {
                        writeln!(&mut text, "HII string package: remained unparsed: 0x{:X}", unp.len()).unwrap();
                    }

                    write!(&mut text, "HII string package: Offset: 0x{:X}, Length: 0x{:X}, Language: {}", i, candidate.len(), string_package.Language).unwrap();
                    i += candidate.len();

                    // Skip languages other than English for now
                    if string_package.Language != "en-US" {
                        writeln!(&mut text, ", skipped").unwrap();
                        continue;
                    }
                    // Ask to split the input file if multiple string packages for English are found
                    if strings_map.len() > 0 {
                        // TODO: some heuristics might be applied here to perform the split automatically
                        //       but they require a different, less generic way to search for HII packages
                        println!("Second HII string package of the same language found at offset 0x{:X}
There is no way for this program to determine what package will be used for a given form
Consider splitting the input file", i - candidate.len());
                        std::process::exit(3);
                    }
                    writeln!(&mut text, "").unwrap();

                    // Parse SIBT blocks
                    match parser::hii_sibt_blocks(string_package.Data) {
                        Ok((unp, sibt_blocks)) => {
                            if unp.len() > 0 {
                                writeln!(&mut text, "SibtBlocks: remained unparsed: 0x{:X}", unp.len()).unwrap();
                            }

                            strings_map.insert(0 as u16, String::new());
                            let mut current_string_index = 1;
                            for block in &sibt_blocks {
                                match block.Type {
                                    // 0x00: End
                                    parser::HiiSibtType::End => {}
                                    // 0x10: StringScsu
                                    parser::HiiSibtType::StringScsu => {
                                        if let Ok((_, string)) = parser::sibt_string_scsu(block.Data.unwrap()) {
                                            strings_map.insert(current_string_index, string);
                                            current_string_index += 1;
                                        }
                                    }
                                    // 0x11: StringScsuFont
                                    parser::HiiSibtType::StringScsuFont => {
                                        if let Ok((_, string)) = parser::sibt_string_scsu_font(block.Data.unwrap()) {
                                            strings_map.insert(current_string_index, string);
                                            current_string_index += 1;
                                        }
                                    }
                                    // 0x12: StringsScsu
                                    parser::HiiSibtType::StringsScsu => {
                                        if let Ok((_, strings)) = parser::sibt_strings_scsu(block.Data.unwrap()) {
                                            for string in strings {
                                                strings_map.insert(current_string_index, string);
                                                current_string_index += 1;
                                            }
                                        }
                                    }
                                    // 0x13: StringsScsuFont
                                    parser::HiiSibtType::StringsScsuFont => {
                                        if let Ok((_, strings)) = parser::sibt_strings_scsu_font(block.Data.unwrap()) {
                                            for string in strings {
                                                strings_map.insert(current_string_index, string);
                                                current_string_index += 1;
                                            }
                                        }
                                    }
                                    // 0x14: StringUcs2
                                    parser::HiiSibtType::StringUcs2 => {
                                        if let Ok((_, string)) = parser::sibt_string_ucs2(block.Data.unwrap()) {
                                            strings_map.insert(current_string_index, string);
                                            current_string_index += 1;
                                        }
                                    }
                                    // 0x15: StringUcs2Font
                                    parser::HiiSibtType::StringUcs2Font => {
                                        if let Ok((_, string)) = parser::sibt_string_ucs2_font(block.Data.unwrap()) {
                                            strings_map.insert(current_string_index, string);
                                            current_string_index += 1;
                                        }
                                    }
                                    // 0x16: StringsUcs2
                                    parser::HiiSibtType::StringsUcs2 => {
                                        if let Ok((_, strings)) = parser::sibt_strings_ucs2(block.Data.unwrap()) {
                                            for string in strings {
                                                strings_map.insert(current_string_index, string);
                                                current_string_index += 1;
                                            }
                                        }
                                    }
                                    // 0x17: StringsUcs2Font
                                    parser::HiiSibtType::StringsUcs2Font => {
                                        if let Ok((_, strings)) = parser::sibt_strings_ucs2_font(block.Data.unwrap()) {
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
                                        current_string_index += count[0] as u16 + 0x100 * count[1] as u16;
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
                        Err(e) => { writeln!(&mut text, "HII SIBT blocks parse error: {:?}", e).unwrap(); }
                    }
                }
                else {
                    i += 1;
                }
            }
            else {
                i += 1;
            }
        }
        else {
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

    // Usage a C-style loop here is ugly, but works fine enough
    // TODO: refactor later
    i = 0;
    while i < data.len() {
        if let Ok((_, candidate)) = parser::hii_form_package_candidate(&data[i..]) {
            if let Ok((_, package)) = parser::hii_package(candidate) {
                i += candidate.len();
                // Parse form package and output it's structure as human-readable strings
                match parser::ifr_operations(package.Data.unwrap()) {
                    Ok((unp, operations)) => {
                        writeln!(&mut text, "HII form package: offset 0x{:X}, length: 0x{:X}", i - candidate.len(), candidate.len()).unwrap();
                        if unp.len() > 0 {
                            writeln!(&mut text, "HII form package: remained unparsed: 0x{:X}", unp.len()).unwrap();
                        }

                        let mut scope_depth = 1;
                        for operation in &operations {
                            if operation.OpCode == parser::IfrOpcode::End {
                                if scope_depth >= 1 {
                                    scope_depth -= 1;
                                }
                            }

                            write!(&mut text, "{:\t<1$}{2:?} ", "", scope_depth, operation.OpCode).unwrap();
                                    
                            match operation.OpCode {
                                // 0x01: Form
                                parser::IfrOpcode::Form => {
                                    match parser::ifr_form(operation.Data.unwrap()) {
                                        Ok((unp, form)) => {
                                            if unp.len() > 0 { write!(&mut text, "Unparsed: 0x{:X}, ", unp.len()).unwrap(); }

                                            write!(&mut text, "FormId: {}, Title: \"{}\"", form.FormId,
                                                strings_map.get(&form.TitleStringId).unwrap_or(&String::from("InvalidId"))).unwrap();
                                        }
                                        Err(e) => { write!(&mut text, "Parse error: {:?}", e).unwrap(); }
                                    }
                                }
                                // 0x02: Subtitle
                                parser::IfrOpcode::Subtitle => {
                                    match parser::ifr_subtitle(operation.Data.unwrap()) {
                                        Ok((unp, sub)) => {
                                            if unp.len() > 0 { write!(&mut text, "Unparsed: 0x{:X}, ", unp.len()).unwrap(); }

                                            write!(&mut text, "Prompt: \"{}\", Help: \"{}\", Flags: 0x{:X}", 
                                                strings_map.get(&sub.PromptStringId).unwrap_or(&String::from("InvalidId")),
                                                strings_map.get(&sub.HelpStringId).unwrap_or(&String::from("InvalidId")), 
                                                sub.Flags).unwrap();
                                        }
                                        Err(e) => { write!(&mut text, "Parse error: {:?}", e).unwrap(); }
                                    }
                                }
                                // 0x03: Text
                                parser::IfrOpcode::Text => {
                                    match parser::ifr_text(operation.Data.unwrap()) {
                                        Ok((unp, txt)) => {
                                            if unp.len() > 0 { write!(&mut text, "Unparsed: 0x{:X}, ", unp.len()).unwrap(); }

                                            write!(&mut text, "Prompt: \"{}\", Help: \"{}\", Text: \"{}\"", 
                                                strings_map.get(&txt.PromptStringId).unwrap_or(&String::from("InvalidId")),
                                                strings_map.get(&txt.HelpStringId).unwrap_or(&String::from("InvalidId")),
                                                strings_map.get(&txt.TextId).unwrap_or(&String::from("InvalidId"))).unwrap();
                                        }
                                        Err(e) => { write!(&mut text, "Parse error: {:?}", e).unwrap(); }
                                    }
                                }
                                // 0x04: Image
                                parser::IfrOpcode::Image => {
                                    match parser::ifr_image(operation.Data.unwrap()) {
                                        Ok((unp, image)) => {
                                            if unp.len() > 0 { write!(&mut text, "Unparsed: 0x{:X}, ", unp.len()).unwrap(); }

                                            write!(&mut text, "ImageId: {}", image.ImageId).unwrap();
                                        }
                                        Err(e) => { write!(&mut text, "Parse error: {:?}", e).unwrap(); }
                                    }
                                }
                                // 0x05: OneOf
                                parser::IfrOpcode::OneOf => {
                                    match parser::ifr_one_of(operation.Data.unwrap()) {
                                        Ok((unp, onf)) => {
                                            if unp.len() > 0 { write!(&mut text, "Unparsed: 0x{:X}, ", unp.len()).unwrap(); }

                                            write!(&mut text, "Prompt: \"{}\", Help: \"{}\", QuestionFlags: 0x{:X}, QuestionId: {}, VarStoreId: {}, VarStoreOffset: 0x{:X}, Flags: 0x{:X}, MinMaxData: {:?}", 
                                                strings_map.get(&onf.PromptStringId).unwrap_or(&String::from("InvalidId")),
                                                strings_map.get(&onf.HelpStringId).unwrap_or(&String::from("InvalidId")),
                                                onf.QuestionFlags,
                                                onf.QuestionId,
                                                onf.VarStoreId,
                                                onf.VarStoreInfo,
                                                onf.Flags,
                                                onf.Data).unwrap();
                                        }
                                        Err(e) => { write!(&mut text, "Parse error: {:?}", e).unwrap(); }
                                    }
                                }
                                // 0x06: CheckBox
                                parser::IfrOpcode::CheckBox => {
                                    match parser::ifr_check_box(operation.Data.unwrap()) {
                                        Ok((unp, cb)) => {
                                            if unp.len() > 0 { write!(&mut text, "Unparsed: 0x{:X}, ", unp.len()).unwrap(); }

                                            write!(&mut text, "Prompt: \"{}\", Help: \"{}\", QuestionFlags: 0x{:X}, QuestionId: {}, VarStoreId: {}, VarStoreOffset: 0x{:X}, Flags: 0x{:X}", 
                                                strings_map.get(&cb.PromptStringId).unwrap_or(&String::from("InvalidId")),
                                                strings_map.get(&cb.HelpStringId).unwrap_or(&String::from("InvalidId")),
                                                cb.QuestionFlags,
                                                cb.QuestionId,
                                                cb.VarStoreId,
                                                cb.VarStoreInfo,
                                                cb.Flags).unwrap();
                                        }
                                        Err(e) => { write!(&mut text, "Parse error: {:?}", e).unwrap(); }
                                    }
                                }
                                // 0x07: Numeric
                                parser::IfrOpcode::Numeric => {
                                    match parser::ifr_numeric(operation.Data.unwrap()) {
                                        Ok((unp, num)) => {
                                            if unp.len() > 0 { write!(&mut text, "Unparsed: 0x{:X}, ", unp.len()).unwrap(); }

                                            write!(&mut text, "Prompt: \"{}\", Help: \"{}\", QuestionFlags: 0x{:X}, QuestionId: {}, VarStoreId: {}, VarStoreOffset: 0x{:X}, Flags: 0x{:X}, MinMaxData: {:?}", 
                                                strings_map.get(&num.PromptStringId).unwrap_or(&String::from("InvalidId")),
                                                strings_map.get(&num.HelpStringId).unwrap_or(&String::from("InvalidId")),
                                                num.QuestionFlags,
                                                num.QuestionId,
                                                num.VarStoreId,
                                                num.VarStoreInfo,
                                                num.Flags,
                                                num.Data).unwrap();
                                        }
                                        Err(e) => { write!(&mut text, "Parse error: {:?}", e).unwrap(); }
                                    }
                                }
                                // 0x08: Password
                                parser::IfrOpcode::Password => {
                                    match parser::ifr_password(operation.Data.unwrap()) {
                                        Ok((unp, pw)) => {
                                            if unp.len() > 0 { write!(&mut text, "Unparsed: 0x{:X}, ", unp.len()).unwrap(); }

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
                                        Err(e) => { write!(&mut text, "Parse error: {:?}", e).unwrap(); }
                                    }
                                }
                                // 0x09: OneOfOption
                                parser::IfrOpcode::OneOfOption => {
                                    match parser::ifr_one_of_option(operation.Data.unwrap()) {
                                        Ok((unp, opt)) => {
                                            if unp.len() > 0 { write!(&mut text, "Unparsed: 0x{:X}, ", unp.len()).unwrap(); }

                                            write!(&mut text, "Option: \"{}\" ", strings_map.get(&opt.OptionStringId).unwrap_or(&String::from("InvalidId"))).unwrap();
                                            match opt.Value {
                                                parser::IfrTypeValue::String(x) => { 
                                                    write!(&mut text, "String: \"{}\"", strings_map.get(&x).unwrap_or(&String::from("InvalidId"))).unwrap(); 
                                                }
                                                parser::IfrTypeValue::Action(x) => { 
                                                    write!(&mut text, "Action: \"{}\"", strings_map.get(&x).unwrap_or(&String::from("InvalidId"))).unwrap(); 
                                                }
                                                _ => {
                                                    write!(&mut text, "Value: {}", opt.Value).unwrap();
                                                }
                                            }
                                        }
                                        Err(e) => { write!(&mut text, "Parse error: {:?}", e).unwrap(); }
                                    }
                                }
                                // 0x0A: SuppressIf
                                parser::IfrOpcode::SuppressIf => {}
                                // 0x0B: Locked
                                parser::IfrOpcode::Locked => {}
                                // 0x0C: Action
                                parser::IfrOpcode::Action => {
                                    match parser::ifr_action(operation.Data.unwrap()) {
                                        Ok((unp, act)) => {
                                            if unp.len() > 0 { write!(&mut text, "Unparsed: 0x{:X}, ", unp.len()).unwrap(); }

                                            write!(&mut text, "Prompt: \"{}\", Help: \"{}\", QuestionFlags: 0x{:X}, QuestionId: {}, VarStoreId: {}, VarStoreInfo: 0x{:X}", 
                                                strings_map.get(&act.PromptStringId).unwrap_or(&String::from("InvalidId")),
                                                strings_map.get(&act.HelpStringId).unwrap_or(&String::from("InvalidId")),
                                                act.QuestionFlags,
                                                act.QuestionId,
                                                act.VarStoreId,
                                                act.VarStoreInfo).unwrap();
                                                if let Some(x) = act.ConfigStringId { write!(&mut text, ", QuestionConfig: {}", strings_map.get(&x).unwrap_or(&String::from("InvalidId"))).unwrap(); }
                                        }
                                        Err(e) => { write!(&mut text, "Parse error: {:?}", e).unwrap(); }
                                    }
                                }
                                // 0x0D: ResetButton
                                parser::IfrOpcode::ResetButton => {
                                    match parser::ifr_reset_button(operation.Data.unwrap()) {
                                        Ok((unp, rst)) => {
                                            if unp.len() > 0 { write!(&mut text, "Unparsed: 0x{:X}, ", unp.len()).unwrap(); }

                                            write!(&mut text, "Prompt: \"{}\", Help: \"{}\", DefaultId: {}", 
                                                strings_map.get(&rst.PromptStringId).unwrap_or(&String::from("InvalidId")),
                                                strings_map.get(&rst.HelpStringId).unwrap_or(&String::from("InvalidId")),
                                                rst.DefaultId).unwrap();
                                        }
                                        Err(e) => { write!(&mut text, "Parse error: {:?}", e).unwrap(); }
                                    }
                                }
                                // 0x0E: FormSet
                                parser::IfrOpcode::FormSet => {
                                    match parser::ifr_form_set(operation.Data.unwrap()) {
                                        Ok((unp, form_set)) => {
                                            if unp.len() > 0 { write!(&mut text, "Unparsed: 0x{:X}, ", unp.len()).unwrap(); }

                                            write!(&mut text, "GUID: {}, Title: \"{}\", Help: \"{}\", Flags: 0x{:X}", form_set.Guid, 
                                                strings_map.get(&form_set.TitleStringId).unwrap_or(&String::from("InvalidId")), 
                                                strings_map.get(&form_set.HelpStringId).unwrap_or(&String::from("InvalidId")),
                                                form_set.Flags).unwrap();
                                        }
                                        Err(e) => { write!(&mut text, "Parse error: {:?}", e).unwrap(); }
                                    }
                                }
                                // 0x0F: Ref
                                parser::IfrOpcode::Ref => {
                                    match parser::ifr_ref(operation.Data.unwrap()) {
                                        Ok((unp, rf)) => {
                                            if unp.len() > 0 { write!(&mut text, "Unparsed: 0x{:X}, ", unp.len()).unwrap(); }

                                            write!(&mut text, "Prompt: \"{}\", Help: \"{}\", QuestionFlags: 0x{:X}, QuestionId: {}, VarStoreId: {}, VarStoreInfo: 0x{:X} ", 
                                                strings_map.get(&rf.PromptStringId).unwrap_or(&String::from("InvalidId")),
                                                strings_map.get(&rf.HelpStringId).unwrap_or(&String::from("InvalidId")),
                                                rf.QuestionFlags,
                                                rf.QuestionId,
                                                rf.VarStoreId,
                                                rf.VarStoreInfo).unwrap();
                                            if let Some(x) = rf.FormId { write!(&mut text, ", FormId: {}", x).unwrap(); }
                                            if let Some(x) = rf.RefQuestionId { write!(&mut text, ", RefQuestionId: {}", x).unwrap(); }
                                            if let Some(x) = rf.FormSetGuid { write!(&mut text, ", FormSetGuid: {}", x).unwrap(); } 
                                            if let Some(x) = rf.DevicePathId { write!(&mut text, ", DevicePathId: {}", x).unwrap(); } 
                                        }
                                        Err(e) => { write!(&mut text, "Parse error: {:?}", e).unwrap(); }
                                    }
                                }
                                // 0x10: NoSubmitIf
                                parser::IfrOpcode::NoSubmitIf => {
                                    match parser::ifr_no_submit_if(operation.Data.unwrap()) {
                                        Ok((unp, ns)) => {
                                            if unp.len() > 0 { write!(&mut text, "Unparsed: 0x{:X}, ", unp.len()).unwrap(); }

                                            write!(&mut text, "Error: \"{}\"", 
                                                strings_map.get(&ns.ErrorStringId).unwrap_or(&String::from("InvalidId"))).unwrap();
                                        }
                                        Err(e) => { write!(&mut text, "Parse error: {:?}", e).unwrap(); }
                                    }
                                }
                                // 0x11: InconsistentIf
                                parser::IfrOpcode::InconsistentIf => {
                                    match parser::ifr_inconsistent_if(operation.Data.unwrap()) {
                                        Ok((unp, inc)) => {
                                            if unp.len() > 0 { write!(&mut text, "Unparsed: 0x{:X}, ", unp.len()).unwrap(); }

                                            write!(&mut text, "Error: \"{}\"", 
                                                strings_map.get(&inc.ErrorStringId).unwrap_or(&String::from("InvalidId"))).unwrap();
                                        }
                                        Err(e) => { write!(&mut text, "Parse error: {:?}", e).unwrap(); }
                                    }
                                }
                                // 0x12: EqIdVal
                                parser::IfrOpcode::EqIdVal => {
                                    match parser::ifr_eq_id_val(operation.Data.unwrap()) {
                                        Ok((unp, eq)) => {
                                            if unp.len() > 0 { write!(&mut text, "Unparsed: 0x{:X}, ", unp.len()).unwrap(); }

                                            write!(&mut text, "QuestionId: {}, Value: {}", eq.QuestionId, eq.Value).unwrap();
                                        }
                                        Err(e) => { write!(&mut text, "Parse error: {:?}", e).unwrap(); }
                                    }
                                }
                                // 0x13: EqIdId
                                parser::IfrOpcode::EqIdId => {
                                    match parser::ifr_eq_id_id(operation.Data.unwrap()) {
                                        Ok((unp, eq)) => {
                                            if unp.len() > 0 { write!(&mut text, "Unparsed: 0x{:X}, ", unp.len()).unwrap(); }

                                            write!(&mut text, "QuestionId: {}, OtherQuestionId: {}", eq.QuestionId, eq.OtherQuestionId).unwrap();
                                        }
                                        Err(e) => { write!(&mut text, "Parse error: {:?}", e).unwrap(); }
                                    }
                                }
                                // 0x14: EqIdValList
                                parser::IfrOpcode::EqIdValList => {
                                    match parser::ifr_eq_id_val_list(operation.Data.unwrap()) {
                                        Ok((unp, eql)) => {
                                            if unp.len() > 0 { write!(&mut text, "Unparsed: 0x{:X}, ", unp.len()).unwrap(); }

                                            write!(&mut text, "QuestionId: {}, Values: {:?}", eql.QuestionId, eql.Values).unwrap();
                                        }
                                        Err(e) => { write!(&mut text, "Parse error: {:?}", e).unwrap(); }
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
                                        Ok((unp, rule)) => {
                                            if unp.len() > 0 { write!(&mut text, "Unparsed: 0x{:X}, ", unp.len()).unwrap(); }

                                            write!(&mut text, "RuleId: {}", rule.RuleId).unwrap();
                                        }
                                        Err(e) => { write!(&mut text, "Parse error: {:?}", e).unwrap(); }
                                    }
                                }
                                // 0x19: GrayOutIf
                                parser::IfrOpcode::GrayOutIf => {}
                                // 0x1A: Date
                                parser::IfrOpcode::Date => {
                                    match parser::ifr_date(operation.Data.unwrap()) {
                                        Ok((unp, dt)) => {
                                            if unp.len() > 0 { write!(&mut text, "Unparsed: 0x{:X}, ", unp.len()).unwrap(); }

                                            write!(&mut text, "Prompt: \"{}\", Help: \"{}\", QuestionFlags: 0x{:X}, QuestionId: {}, VarStoreId: {}, VarStoreInfo: 0x{:X}, Flags: 0x{:X}", 
                                                strings_map.get(&dt.PromptStringId).unwrap_or(&String::from("InvalidId")),
                                                strings_map.get(&dt.HelpStringId).unwrap_or(&String::from("InvalidId")),
                                                dt.QuestionFlags,
                                                dt.QuestionId,
                                                dt.VarStoreId,
                                                dt.VarStoreInfo,
                                                dt.Flags).unwrap();
                                        }
                                        Err(e) => { write!(&mut text, "Parse error: {:?}", e).unwrap(); }
                                    }
                                }
                                // 0x1B: Time
                                parser::IfrOpcode::Time => {
                                    match parser::ifr_time(operation.Data.unwrap()) {
                                        Ok((unp, time)) => {
                                            if unp.len() > 0 { write!(&mut text, "Unparsed: 0x{:X}, ", unp.len()).unwrap(); }

                                            write!(&mut text, "Prompt: \"{}\", Help: \"{}\", QuestionFlags: 0x{:X}, QuestionId: {}, VarStoreId: {}, VarStoreInfo: 0x{:X}, Flags: 0x{:X}", 
                                                strings_map.get(&time.PromptStringId).unwrap_or(&String::from("InvalidId")),
                                                strings_map.get(&time.HelpStringId).unwrap_or(&String::from("InvalidId")),
                                                time.QuestionFlags,
                                                time.QuestionId,
                                                time.VarStoreId,
                                                time.VarStoreInfo,
                                                time.Flags).unwrap();
                                        }
                                        Err(e) => { write!(&mut text, "Parse error: {:?}", e).unwrap(); }
                                    }
                                }
                                // 0x1C: String
                                parser::IfrOpcode::String => {
                                    match parser::ifr_string(operation.Data.unwrap()) {
                                        Ok((unp, st)) => {
                                            if unp.len() > 0 { write!(&mut text, "Unparsed: 0x{:X}, ", unp.len()).unwrap(); }

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
                                        Err(e) => { write!(&mut text, "Parse error: {:?}", e).unwrap(); }
                                    }
                                }
                                // 0x1D: Refresh
                                parser::IfrOpcode::Refresh => {
                                    match parser::ifr_refresh(operation.Data.unwrap()) {
                                        Ok((unp, refr)) => {
                                            if unp.len() > 0 { write!(&mut text, "Unparsed: 0x{:X}, ", unp.len()).unwrap(); }

                                            write!(&mut text, "RefreshInterval: {}", refr.RefreshInterval).unwrap();
                                        }
                                        Err(e) => { write!(&mut text, "Parse error: {:?}", e).unwrap(); }
                                    }
                                }
                                // 0x1E: DisableIf
                                parser::IfrOpcode::DisableIf => {}
                                // 0x1F: Animation
                                parser::IfrOpcode::Animation => {
                                    match parser::ifr_animation(operation.Data.unwrap()) {
                                        Ok((unp, anim)) => {
                                            if unp.len() > 0 { write!(&mut text, "Unparsed: 0x{:X}, ", unp.len()).unwrap(); }

                                            write!(&mut text, "AnimationId: {}", anim.AnimationId).unwrap();
                                        }
                                        Err(e) => { write!(&mut text, "Parse error: {:?}", e).unwrap(); }
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
                                        Ok((unp, ol)) => {
                                            if unp.len() > 0 { write!(&mut text, "Unparsed: 0x{:X}, ", unp.len()).unwrap(); }

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
                                        Err(e) => { write!(&mut text, "Parse error: {:?}", e).unwrap(); }
                                    }
                                }
                                // 0x24: VarStore
                                parser::IfrOpcode::VarStore => {
                                    match parser::ifr_var_store(operation.Data.unwrap()) {
                                        Ok((unp, var_store)) => {
                                            if unp.len() > 0 { write!(&mut text, "Unparsed: 0x{:X}, ", unp.len()).unwrap(); }

                                            write!(&mut text, "GUID: {}, VarStoreId: {}, Size: 0x{:X}, Name: \"{}\"", 
                                                var_store.Guid, 
                                                var_store.VarStoreId, 
                                                var_store.Size, 
                                                var_store.Name).unwrap();
                                        }
                                        Err(e) => { write!(&mut text, "Parse error: {:?}", e).unwrap(); }
                                    }
                                }
                                // 0x25: VarStoreNameValue
                                parser::IfrOpcode::VarStoreNameValue => {
                                    match parser::ifr_var_store_name_value(operation.Data.unwrap()) {
                                        Ok((unp, var_store)) => {
                                            if unp.len() > 0 { write!(&mut text, "Unparsed: 0x{:X}, ", unp.len()).unwrap(); }

                                            write!(&mut text, "GUID: {}, VarStoreId: {}", var_store.Guid, var_store.VarStoreId).unwrap();
                                        }
                                        Err(e) => { write!(&mut text, "Parse error: {:?}", e).unwrap(); }
                                    }
                                }
                                // 0x26: VarStoreEfi258
                                parser::IfrOpcode::VarStoreEfi => {
                                    match parser::ifr_var_store_efi(operation.Data.unwrap()) {
                                        Ok((unp, var_store)) => {
                                            if unp.len() > 0 { write!(&mut text, "Unparsed: 0x{:X}, ", unp.len()).unwrap(); }

                                            write!(&mut text, "GUID: {}, VarStoreId: {}, Attributes: 0x{:X}, Size: 0x{:X}, Name: \"{}\"", 
                                                var_store.Guid, 
                                                var_store.VarStoreId, 
                                                var_store.Attributes, 
                                                var_store.Size, 
                                                var_store.Name).unwrap();
                                        }
                                        Err(e) => { write!(&mut text, "Parse error: {:?}", e).unwrap(); }
                                    }
                                }
                                // 0x27: VarStoreDevice
                                parser::IfrOpcode::VarStoreDevice => {
                                    match parser::ifr_var_store_device(operation.Data.unwrap()) {
                                        Ok((unp, var_store)) => {
                                            if unp.len() > 0 { write!(&mut text, "Unparsed: 0x{:X}, ", unp.len()).unwrap(); }

                                            write!(&mut text, "DevicePath: \"{}\"", 
                                            strings_map.get(&var_store.DevicePathStringId).unwrap_or(&String::from("InvalidId"))).unwrap();
                                        }
                                        Err(e) => { write!(&mut text, "Parse error: {:?}", e).unwrap(); }
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
                                        Ok((unp, get)) => {
                                            if unp.len() > 0 { write!(&mut text, "Unparsed: 0x{:X}, ", unp.len()).unwrap(); }

                                            write!(&mut text, "VarStoreId: {}, VarStoreInfo: {}, VarStoreType: {}", 
                                                get.VarStoreId,
                                                get.VarStoreInfo,
                                                get.VarStoreType).unwrap();
                                        }
                                        Err(e) => { write!(&mut text, "Parse error: {:?}", e).unwrap(); }
                                    }
                                }
                                // 0x2C: Set
                                parser::IfrOpcode::Set => {
                                    match parser::ifr_set(operation.Data.unwrap()) {
                                        Ok((unp, set)) => {
                                            if unp.len() > 0 { write!(&mut text, "Unparsed: 0x{:X}, ", unp.len()).unwrap(); }

                                            write!(&mut text, "VarStoreId: {}, VarStoreInfo: {}, VarStoreType: {}", 
                                                set.VarStoreId,
                                                set.VarStoreInfo,
                                                set.VarStoreType).unwrap();
                                        }
                                        Err(e) => { write!(&mut text, "Parse error: {:?}", e).unwrap(); }
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
                                        Ok((unp, rule)) => {
                                            if unp.len() > 0 { write!(&mut text, "Unparsed: 0x{:X}, ", unp.len()).unwrap(); }

                                            write!(&mut text, "RuleId: {}", rule.RuleId).unwrap();
                                        }
                                        Err(e) => { write!(&mut text, "Parse error: {:?}", e).unwrap(); }
                                    }
                                }
                                // 0x40: QuestionRef1
                                parser::IfrOpcode::QuestionRef1 => {
                                    match parser::ifr_question_ref_1(operation.Data.unwrap()) {
                                        Ok((unp, qr)) => {
                                            if unp.len() > 0 { write!(&mut text, "Unparsed: 0x{:X}, ", unp.len()).unwrap(); }

                                            write!(&mut text, "QuestionId: {}", qr.QuestionId).unwrap();
                                        }
                                        Err(e) => { write!(&mut text, "Parse error: {:?}", e).unwrap(); }
                                    }
                                }
                                // 0x41: QuestionRef2
                                parser::IfrOpcode::QuestionRef2 => {}
                                // 0x42: Uint8
                                parser::IfrOpcode::Uint8 => {
                                    match parser::ifr_uint8(operation.Data.unwrap()) {
                                        Ok((unp, u)) => {
                                            if unp.len() > 0 { write!(&mut text, "Unparsed: 0x{:X}, ", unp.len()).unwrap(); }

                                            write!(&mut text, "Value: {}", u.Value).unwrap();
                                        }
                                        Err(e) => { write!(&mut text, "Parse error: {:?}", e).unwrap(); }
                                    }
                                }
                                // 0x43: Uint16
                                parser::IfrOpcode::Uint16 => {
                                    match parser::ifr_uint16(operation.Data.unwrap()) {
                                        Ok((unp, u)) => {
                                            if unp.len() > 0 { write!(&mut text, "Unparsed: 0x{:X}, ", unp.len()).unwrap(); }

                                            write!(&mut text, "Value: {}", u.Value).unwrap();
                                        }
                                        Err(e) => { write!(&mut text, "Parse error: {:?}", e).unwrap(); }
                                    }
                                }
                                // 0x44: Uint32
                                parser::IfrOpcode::Uint32 => {
                                    match parser::ifr_uint32(operation.Data.unwrap()) {
                                        Ok((unp, u)) => {
                                            if unp.len() > 0 { write!(&mut text, "Unparsed: 0x{:X}, ", unp.len()).unwrap(); }

                                            write!(&mut text, "Value: {}", u.Value).unwrap();
                                        }
                                        Err(e) => { write!(&mut text, "Parse error: {:?}", e).unwrap(); }
                                    }
                                }
                                // 0x45: Uint64
                                parser::IfrOpcode::Uint64 => {
                                    match parser::ifr_uint64(operation.Data.unwrap()) {
                                        Ok((unp, u)) => {
                                            if unp.len() > 0 { write!(&mut text, "Unparsed: 0x{:X}, ", unp.len()).unwrap(); }

                                            write!(&mut text, "Value: {}", u.Value).unwrap();
                                        }
                                        Err(e) => { write!(&mut text, "Parse error: {:?}", e).unwrap(); }
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
                                        Ok((unp, ts)) => {
                                            if unp.len() > 0 { write!(&mut text, "Unparsed: 0x{:X}, ", unp.len()).unwrap(); }

                                            write!(&mut text, "Format: 0x{:X}", ts.Format).unwrap();
                                        }
                                        Err(e) => { write!(&mut text, "Parse error: {:?}", e).unwrap(); }
                                    }
                                }
                                // 0x4A: ToBoolean
                                parser::IfrOpcode::ToBoolean => {}
                                // 0x4B: Mid
                                parser::IfrOpcode::Mid => {}
                                // 0x4C: Find
                                parser::IfrOpcode::Find => {
                                    match parser::ifr_find(operation.Data.unwrap()) {
                                        Ok((unp, fnd)) => {
                                            if unp.len() > 0 { write!(&mut text, "Unparsed: 0x{:X}, ", unp.len()).unwrap(); }

                                            write!(&mut text, "Format: 0x{:X}", fnd.Format).unwrap();
                                        }
                                        Err(e) => { write!(&mut text, "Parse error: {:?}", e).unwrap(); }
                                    }
                                }
                                // 0x4D: Token
                                parser::IfrOpcode::Token => {}
                                // 0x4E: StringRef1
                                parser::IfrOpcode::StringRef1 => {
                                    match parser::ifr_string_ref_1(operation.Data.unwrap()) {
                                        Ok((unp, st)) => {
                                            if unp.len() > 0 { write!(&mut text, "Unparsed: 0x{:X}, ", unp.len()).unwrap(); }

                                            write!(&mut text, "String: \"{}\"", 
                                            strings_map.get(&st.StringId).unwrap_or(&String::from("InvalidId"))).unwrap();
                                        }
                                        Err(e) => { write!(&mut text, "Parse error: {:?}", e).unwrap(); }
                                    }
                                }
                                // 0x4F: StringRef2
                                parser::IfrOpcode::StringRef2 => {}
                                // 0x50: Conditional
                                parser::IfrOpcode::Conditional => {}
                                // 0x51: QuestionRef3
                                parser::IfrOpcode::QuestionRef3 => {
                                    if operation.Length > 2 {
                                        match parser::ifr_question_ref_3(operation.Data.unwrap()) {
                                            Ok((unp, qr)) => {
                                                if unp.len() > 0 { write!(&mut text, "Unparsed: 0x{:X}, ", unp.len()).unwrap(); }

                                                if let Some(x) = qr.DevicePathId {
                                                    write!(&mut text, "DevicePath: \"{}\"", 
                                                    strings_map.get(&x).unwrap_or(&String::from("InvalidId"))).unwrap();
                                                }
                                                if let Some(x) = qr.QuestionGuid {
                                                    write!(&mut text, "Guid: {}", x).unwrap();
                                                }
                                            }
                                            Err(e) => { write!(&mut text, "Parse error: {:?}", e).unwrap(); }
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
                                        Ok((unp, span)) => {
                                            if unp.len() > 0 { write!(&mut text, "Unparsed: 0x{:X}, ", unp.len()).unwrap(); }

                                            write!(&mut text, "Flags: 0x{:X}", span.Flags).unwrap();
                                        }
                                        Err(e) => { write!(&mut text, "Parse error: {:?}", e).unwrap(); }
                                    }
                                }
                                // 0x5A: Value
                                parser::IfrOpcode::Value => {}
                                // 0x5B: Default
                                parser::IfrOpcode::Default => {
                                    match parser::ifr_default(operation.Data.unwrap()) {
                                        Ok((unp, def)) => {
                                            if unp.len() > 0 { write!(&mut text, "Unparsed: 0x{:X}, ", unp.len()).unwrap(); }

                                            write!(&mut text, "DefaultId: {} ", def.DefaultId).unwrap(); 
                                            match def.Value {
                                                parser::IfrTypeValue::String(x) => { 
                                                    write!(&mut text, "String: \"{}\"", strings_map.get(&x).unwrap_or(&String::from("InvalidId"))).unwrap(); 
                                                }
                                                parser::IfrTypeValue::Action(x) => { 
                                                    write!(&mut text, "Action: \"{}\"", strings_map.get(&x).unwrap_or(&String::from("InvalidId"))).unwrap(); 
                                                }
                                                _ => {
                                                    write!(&mut text, "Value: {}", def.Value).unwrap();
                                                }
                                            }
                                        }
                                        Err(e) => { write!(&mut text, "Parse error: {:?}", e).unwrap(); }
                                    }
                                }
                                // 0x5C: DefaultStore
                                parser::IfrOpcode::DefaultStore => {
                                    match parser::ifr_default_store(operation.Data.unwrap()) {
                                        Ok((unp, default_store)) => {
                                            if unp.len() > 0 { write!(&mut text, "Unparsed: 0x{:X}, ", unp.len()).unwrap(); }

                                            write!(&mut text, "DefaultId: {}, Name: \"{}\"", default_store.DefaultId,
                                                strings_map.get(&default_store.NameStringId).unwrap_or(&String::from("InvalidId"))).unwrap();
                                        }
                                        Err(e) => { write!(&mut text, "Parse error: {:?}", e).unwrap(); }
                                    }
                                }
                                // 0x5D: FormMap
                                parser::IfrOpcode::FormMap => {
                                    match parser::ifr_form_map(operation.Data.unwrap()) {
                                        Ok((unp, form_map)) => {
                                            if unp.len() > 0 { write!(&mut text, "Unparsed: 0x{:X}, ", unp.len()).unwrap(); }

                                            write!(&mut text, "FormId: {}", form_map.FormId).unwrap();
                                            for method in form_map.Methods {
                                                 write!(&mut text, "| GUID: {}, Method: \"{}\"", method.MethodIdentifier,
                                                 strings_map.get(&method.MethodTitle).unwrap_or(&String::from("InvalidId"))).unwrap();
                                            }
                                        }
                                        Err(e) => { write!(&mut text, "Parse error: {:?}", e).unwrap(); }
                                    }
                                }
                                // 0x5E: Catenate
                                parser::IfrOpcode::Catenate => {}
                                // 0x5F: GUID
                                parser::IfrOpcode::Guid => {
                                    match parser::ifr_guid(operation.Data.unwrap()) {
                                        Ok((unp, guid)) => {
                                            if unp.len() > 0 { write!(&mut text, "Unparsed: 0x{:X}, ", unp.len()).unwrap(); }

                                            // This manual parsing here is ugly and can ultimately be done using nom, 
                                            // but it's done already and not that important anyway
                                            // TODO: refactor later
                                            let mut done = false;
                                            match guid.Guid {
                                                parser::IFR_TIANO_GUID => {
                                                    if let Ok((_, edk2)) = parser::ifr_guid_edk2(guid.Data) {
                                                        match edk2.ExtendedOpCode {
                                                            parser::IfrEdk2ExtendOpCode::Banner => {
                                                                if let Ok((_, banner)) = parser::ifr_guid_edk2_banner(edk2.Data) {
                                                                    write!(&mut text, "Guid: {}, ExtendedOpCode: {:?}, Title: \"{}\", LineNumber: {}, Alignment: {} ", 
                                                                    guid.Guid, 
                                                                    edk2.ExtendedOpCode,
                                                                    strings_map.get(&banner.Title).unwrap_or(&String::from("InvalidId")),
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
                                                    if let Ok((_, edk)) = parser::ifr_guid_edk(guid.Data) {
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
                                                write!(&mut text, "Guid: {}, Optional data: {:?}", guid.Guid, guid.Data).unwrap();
                                            }
                                        }
                                        Err(e) => { write!(&mut text, "Parse error: {:?}", e).unwrap(); }
                                    }
                                }
                                // 0x60: Security
                                parser::IfrOpcode::Security => {
                                    match parser::ifr_security(operation.Data.unwrap()) {
                                        Ok((unp, sec)) => {
                                            if unp.len() > 0 { write!(&mut text, "Unparsed: 0x{:X}, ", unp.len()).unwrap(); }

                                            write!(&mut text, "Guid: {}", sec.Guid).unwrap();
                                        }
                                        Err(e) => { write!(&mut text, "Parse error: {:?}", e).unwrap(); }
                                    }
                                }
                                // 0x61: ModalTag
                                parser::IfrOpcode::ModalTag => {}
                                // 0x62: RefreshId
                                parser::IfrOpcode::RefreshId => {
                                    match parser::ifr_refresh_id(operation.Data.unwrap()) {
                                        Ok((unp, rid)) => {
                                            if unp.len() > 0 { write!(&mut text, "Unparsed: 0x{:X}, ", unp.len()).unwrap(); }

                                            write!(&mut text, "Guid: {}", rid.Guid).unwrap();
                                        }
                                        Err(e) => { write!(&mut text, "Parse error: {:?}", e).unwrap(); }
                                    }
                                }
                                // 0x63: WarningIf
                                parser::IfrOpcode::WarningIf => {
                                    match parser::ifr_warning_if(operation.Data.unwrap()) {
                                        Ok((unp, warn)) => {
                                            if unp.len() > 0 { write!(&mut text, "Unparsed: 0x{:X}, ", unp.len()).unwrap(); }

                                            write!(&mut text, "Timeout: {}, Warning: \"{}\"", warn.Timeout,
                                                strings_map.get(&warn.WarningStringId).unwrap_or(&String::from("InvalidId"))).unwrap();
                                        }
                                        Err(e) => { write!(&mut text, "Parse error: {:?}", e).unwrap(); }
                                    }
                                }
                                // 0x64: Match2
                                parser::IfrOpcode::Match2 => {
                                    match parser::ifr_match_2(operation.Data.unwrap()) {
                                        Ok((unp, m2)) => {
                                            if unp.len() > 0 { write!(&mut text, "Unparsed: 0x{:X}, ", unp.len()).unwrap(); }

                                            write!(&mut text, "Guid: {}", m2.Guid).unwrap();
                                        }
                                        Err(e) => { write!(&mut text, "Parse error: {:?}", e).unwrap(); }
                                    }
                                }
                                // Unknown operation
                                parser::IfrOpcode::Unknown(x) => {write!(&mut text, " - can't parse IFR operation of unknown type 0x{:X}", x).unwrap();}
                            }
                            writeln!(&mut text, "").unwrap();

                            if operation.ScopeStart == true {
                                scope_depth += 1;
                            }
                        }
                    }
                    Err(e) => { writeln!(&mut text, "IFR operations parse error: {:?}", e).unwrap(); }
                }
            }
            else {
                i += 1;
            }
        }
        else {
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
    output_file.write(&text).expect(&format!("Can't write to output file {:?}", file_path));
}
