#![allow(non_snake_case)]
#![allow(deprecated)]

extern crate nom;

use nom::{le_u16, le_u32, le_u64, le_u8, rest, IResult};
use std::fmt;

//
// Common data types
//
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

pub fn guid(input: &[u8]) -> IResult<&[u8], Guid> {
    do_parse!(
        input,
        d1: le_u32
            >> d2: le_u16
            >> d3: le_u16
            >> d4: count_fixed!(u8, le_u8, 8)
            >> (Guid {
                data1: d1,
                data2: d2,
                data3: d3,
                data4: d4,
            })
    )
}

impl fmt::Display for Guid {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            self.data1,
            self.data2,
            self.data3,
            self.data4[0],
            self.data4[1],
            self.data4[2],
            self.data4[3],
            self.data4[4],
            self.data4[5],
            self.data4[6],
            self.data4[7]
        )
    }
}

//
// HII package header
//
#[derive(Debug, PartialEq, Eq)]
pub struct HiiPackage<'a> {
    pub Length: u32, // 24 bits
    pub Type: HiiPackageType,
    pub Data: Option<&'a [u8]>,
}

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum HiiPackageType {
    Guid,
    Form,
    KeyboardLayout,
    Strings,
    Fonts,
    Images,
    SimpleFonts,
    DevicePath,
    End,
    System(u8),
    Unknown(u8),
}

impl From<u8> for HiiPackageType {
    fn from(n: u8) -> HiiPackageType {
        match n {
            0x01 => HiiPackageType::Guid,
            0x02 => HiiPackageType::Form,
            0x03 => HiiPackageType::KeyboardLayout,
            0x04 => HiiPackageType::Strings,
            0x05 => HiiPackageType::Fonts,
            0x06 => HiiPackageType::Images,
            0x07 => HiiPackageType::SimpleFonts,
            0x08 => HiiPackageType::DevicePath,
            0xDF => HiiPackageType::End,
            0xE0..=0xFF => HiiPackageType::System(n),
            _ => HiiPackageType::Unknown(n),
        }
    }
}

pub fn hii_package(input: &[u8]) -> IResult<&[u8], HiiPackage> {
    do_parse!(
        input,
        len_raw: le_u32
            >> len: verify!(value!(len_raw & 0xFFFFFF), |val: u32| val >= 4)
            >> typ: value!(((len_raw & 0xFF000000) >> 24) as u8)
            >> data: cond_with_error!(len > 4, take!(len - 4))
            >> (HiiPackage {
                Length: len,
                Type: HiiPackageType::from(typ),
                Data: data,
            })
    )
}

pub fn hii_string_package_candidate(input: &[u8]) -> IResult<&[u8], &[u8]> {
    do_parse!(
        input,
        len: peek!(hii_string_package_candidate_helper) >> dat: take!(len) >> (dat)
    )
}

fn hii_string_package_candidate_helper(input: &[u8]) -> IResult<&[u8], usize> {
    do_parse!(
        input,
        len_raw: le_u32 >>
        len: verify!(value!(len_raw & 0x00FFFFFF), |val: u32| val > 0x04 + 0x34) >> // Total length of the package is sane
        verify!(value!(len_raw & 0xFF000000), |val: u32| val == 0x04000000) >> // Package type is 0x04 
        verify!(le_u32, |val: u32| val == 0x34) >> // Header size is 0x34
        take!(len - 0x04 - 0x04 - 0x02) >> // Skip the rest up to the last 2 bytes
        verify!(le_u16, |val: u16| val == 0) >> // Last 2 bytes must be zeroes
        ( len as usize )
    )
}

pub fn hii_form_package_candidate(input: &[u8]) -> IResult<&[u8], &[u8]> {
    do_parse!(
        input,
        len: peek!(hii_form_package_candidate_helper) >> dat: take!(len) >> (dat)
    )
}

fn hii_form_package_candidate_helper(input: &[u8]) -> IResult<&[u8], usize> {
    do_parse!(
        input,
        len_raw: le_u32 >>
        len: verify!(value!(len_raw & 0x00FFFFFF), |val: u32| val > 0x4) >> // Total length of the package is sane
        verify!(value!(len_raw & 0xFF000000), |val: u32| val == 0x02000000) >> // Package type is 0x02 
        verify!(le_u8, |val: u8| val == 0x0E) >> // Must start with IfrOpCode::FormSet
        take!(len - 0x04 - 0x01 - 0x02) >> // Skip the rest up to the last 2 bytes
        verify!(le_u16, |val: u16| val == 0x0229) >> // Last 2 bytes must be IfrOpCode::End
        ( len as usize )
    )
}

//
// HII string package
//
#[derive(Debug, PartialEq, Eq)]
pub struct HiiStringPackage<'a> {
    pub HdrSize: u32,
    pub StringInfoOffset: u32,
    pub LanguageWindow: [u16; 16], // UCS2 string
    pub LanguageName: u16,
    pub Language: String,
    pub Data: &'a [u8],
}

pub fn hii_string_package(input: &[u8]) -> IResult<&[u8], HiiStringPackage> {
    do_parse!(
        input,
        hs  : verify!(le_u32, |val: u32| val == 0x34) >>
        sio : le_u32 >>
        lw  : count_fixed!(u16, le_u16, 16) >>
        ln  : le_u16 >>
        lg  : take!(hs - 0x2F) >>
              take!(1) >> // Skip terminating zero 
        d   : rest >>
        ( HiiStringPackage {
            HdrSize : hs,
            StringInfoOffset : sio,
            LanguageWindow : lw,
            LanguageName : ln,
            Language : String::from_utf8_lossy(lg).to_string(),
            Data : d,
            }
        )
    )
}

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum HiiSibtType {
    End,
    StringScsu,
    StringScsuFont,
    StringsScsu,
    StringsScsuFont,
    StringUcs2,
    StringUcs2Font,
    StringsUcs2,
    StringsUcs2Font,
    Duplicate,
    Skip2,
    Skip1,
    Ext1,
    Ext2,
    Ext4,
    Unknown(u8),
}

impl From<u8> for HiiSibtType {
    fn from(n: u8) -> HiiSibtType {
        match n {
            0x00 => HiiSibtType::End,
            0x10 => HiiSibtType::StringScsu,
            0x11 => HiiSibtType::StringScsuFont,
            0x12 => HiiSibtType::StringsScsu,
            0x13 => HiiSibtType::StringsScsuFont,
            0x14 => HiiSibtType::StringUcs2,
            0x15 => HiiSibtType::StringUcs2Font,
            0x16 => HiiSibtType::StringsUcs2,
            0x17 => HiiSibtType::StringsUcs2Font,
            0x20 => HiiSibtType::Duplicate,
            0x21 => HiiSibtType::Skip2,
            0x22 => HiiSibtType::Skip1,
            0x30 => HiiSibtType::Ext1,
            0x31 => HiiSibtType::Ext2,
            0x32 => HiiSibtType::Ext4,
            _ => HiiSibtType::Unknown(n),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct HiiSibtBlock<'a> {
    pub Type: HiiSibtType,
    pub Data: Option<&'a [u8]>,
}

pub fn hii_sibt_blocks(input: &[u8]) -> IResult<&[u8], Vec<HiiSibtBlock>> {
    do_parse!(input, v: many1!(complete!(hii_sibt_block)) >> (v))
}

pub fn hii_sibt_block(input: &[u8]) -> IResult<&[u8], HiiSibtBlock> {
    do_parse!(
        input,
        typ: peek!(le_u8)
            >> len: switch!(le_u8,
                0x00 => value!(0) | // End block has no data
                0x10 => peek!(do_parse!(s: scsu_string >> (s.len()))) | // Just SCSU string
                0x11 => peek!(do_parse!(take!(1) >> s: scsu_string >> (s.len()))) | // One u8 and SCSU string
                0x12 => peek!(do_parse!(cnt: le_u16 >>
                                        v: count!(do_parse!(s: scsu_string >> (s.len())), cnt as usize) >>
                                        ( v.iter().sum() ))) | // One u16 as count, and a number of SCSU strings
                0x12 => peek!(do_parse!(take!(1) >>
                                        cnt: le_u16 >>
                                        v: count!(do_parse!(s: scsu_string >> (s.len())), cnt as usize) >>
                                        ( v.iter().sum() ))) | // One u8, one u16 as count and a number of SCSU strings
                0x14 => peek!(do_parse!(s: ucs2_string >> (s.len() * 2))) | // Just UCS2 string
                0x15 => peek!(do_parse!(take!(1) >> s: ucs2_string >> (s.len()*2))) | // One u8 and UCS2 string
                0x16 => peek!(do_parse!(cnt: le_u16 >>
                                        v: count!(do_parse!(s: ucs2_string >> (s.len()*2)), cnt as usize) >>
                                        ( v.iter().sum() ))) | // One u16 as count, and a number of UCS2 strings
                0x17 => peek!(do_parse!(take!(1) >>
                                        cnt: le_u16 >>
                                        v: count!(do_parse!(s: ucs2_string >> (s.len()*2)), cnt as usize) >>
                                        ( v.iter().sum() ))) | // One u8, one u16 as count, and a number of UCS2 strings
                0x20 => value!(2) | // Duplicate block has one u16
                0x21 => value!(2) | // Skip2 block has one u16
                0x22 => value!(1) | // Skip1 block has one u8
                0x30 => peek!(do_parse!(le_u8 >>
                                  l: le_u8 >>
                                  take!(l as usize) >>
                                  ( l as usize ))) | // Obtain length from Ext1 block
                0x31 => peek!(do_parse!(le_u8 >>
                                  l: le_u16 >>
                                  take!(l as usize) >>
                                  ( l as usize ))) | // Obtain length from Ext2 block
                0x32 => peek!(do_parse!(le_u8 >>
                                  l: le_u32 >>
                                  take!(l as usize) >>
                                  ( l as usize )))  // Obtain length from Ext4 block
            )
            >> dat: cond_with_error!(len > 0, take!(len))
            >> (HiiSibtBlock {
                Type: HiiSibtType::from(typ),
                Data: dat,
            })
    )
}

named!(
    ucs2_string<Vec<u16>>,
    map!(
        many_till!(le_u16, verify!(le_u16, |n: u16| n == 0)),
        |(mut v, n)| {
            v.push(n);
            v
        }
    )
);

named!(
    scsu_string<Vec<u8>>,
    map!(many_till!(le_u8, verify!(le_u8, |n: u8| n == 0)), |(
        mut v,
        n,
    )| {
        v.push(n);
        v
    })
);

pub fn sibt_string_scsu(input: &[u8]) -> IResult<&[u8], String> {
    do_parse!(
        input,
        s: scsu_string >> (String::from_utf8_lossy(&s[..s.len() - 1]).to_string())
    )
}

pub fn sibt_string_scsu_font(input: &[u8]) -> IResult<&[u8], String> {
    do_parse!(
        input,
        take!(1) >> s: scsu_string >> (String::from_utf8_lossy(&s[..s.len() - 1]).to_string())
    )
}

pub fn sibt_strings_scsu(input: &[u8]) -> IResult<&[u8], Vec<String>> {
    do_parse!(
        input,
        cnt: le_u16
            >> v: count!(
                do_parse!(
                    s: scsu_string >> (String::from_utf8_lossy(&s[..s.len() - 1]).to_string())
                ),
                cnt as usize
            )
            >> (v)
    )
}

pub fn sibt_strings_scsu_font(input: &[u8]) -> IResult<&[u8], Vec<String>> {
    do_parse!(
        input,
        take!(1)
            >> cnt: le_u16
            >> v: count!(
                do_parse!(
                    s: scsu_string >> (String::from_utf8_lossy(&s[..s.len() - 1]).to_string())
                ),
                cnt as usize
            )
            >> (v)
    )
}

pub fn sibt_string_ucs2(input: &[u8]) -> IResult<&[u8], String> {
    do_parse!(
        input,
        s: ucs2_string >> (String::from_utf16_lossy(&s[..s.len() - 1]))
    )
}

pub fn sibt_string_ucs2_font(input: &[u8]) -> IResult<&[u8], String> {
    do_parse!(
        input,
        take!(1) >> s: ucs2_string >> (String::from_utf16_lossy(&s[..s.len() - 1]))
    )
}

pub fn sibt_strings_ucs2(input: &[u8]) -> IResult<&[u8], Vec<String>> {
    do_parse!(
        input,
        cnt: le_u16
            >> v: count!(
                do_parse!(s: ucs2_string >> (String::from_utf16_lossy(&s[..s.len() - 1]))),
                cnt as usize
            )
            >> (v)
    )
}

pub fn sibt_strings_ucs2_font(input: &[u8]) -> IResult<&[u8], Vec<String>> {
    do_parse!(
        input,
        take!(1)
            >> cnt: le_u16
            >> v: count!(
                do_parse!(s: ucs2_string >> (String::from_utf16_lossy(&s[..s.len() - 1]))),
                cnt as usize
            )
            >> (v)
    )
}

//
// HII form package
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrOperation<'a> {
    pub OpCode: IfrOpcode,
    pub Length: u8,
    pub ScopeStart: bool,
    pub Data: Option<&'a [u8]>,
}

pub fn ifr_operation(input: &[u8]) -> IResult<&[u8], IfrOperation> {
    do_parse!(
        input,
        opcode: le_u8
            >> len_raw: le_u8
            >> len: verify!(value!(len_raw & 0x7F), |val: u8| val >= 2)
            >> data: cond_with_error!(len > 2, take!((len - 2) as usize))
            >> (IfrOperation {
                OpCode: IfrOpcode::from(opcode),
                Length: len,
                ScopeStart: (len_raw & 0x80) == 0x80,
                Data: data
            })
    )
}

pub fn ifr_operations(input: &[u8]) -> IResult<&[u8], Vec<IfrOperation>> {
    do_parse!(input, v: many1!(complete!(ifr_operation)) >> (v))
}

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum IfrOpcode {
    Form,              // Form
    Subtitle,          // Subtible
    Text,              // Static text
    Image,             // Static image
    OneOf,             // One-of question
    CheckBox,          // Boolean question
    Numeric,           // Numeric question
    Password,          // Password string question
    OneOfOption,       // Option
    SuppressIf,        // Suppress-if conditional
    Locked,            // Marks statement as locked
    Action,            // Button question
    ResetButton,       // Reset button
    FormSet,           // Form set
    Ref,               // Cross-reference
    NoSubmitIf,        // Error checking conditional
    InconsistentIf,    // Error checking conditional
    EqIdVal,           // Return true if question value equals UINT16
    EqIdId,            // Return true if question value equals another question value
    EqIdValList,       // Return true if question value is found in list of UINT16s
    And,               // Push true if both sub-expression returns true
    Or,                // Push true if either sub-expressions returns true
    Not,               // Push false if sub-expression returns true, otherwise push true
    Rule,              // Create rule in current form
    GrayOutIf, // Nested statements, questions or options will not be selectable if expression returns true
    Date,      // Date
    Time,      // Time
    String,    // String
    Refresh,   // Interval for refreshing a question
    DisableIf, // Nested statements, questions or options will not be processed if expression returns true
    Animation, // Animation associated with question statement, form or form set
    ToLower,   // Convert a string on the expression stack to lower case
    ToUpper,   // Convert a string on the expression stack to upper case
    Map,       // Convert one value to another by selecting a match from a list
    OrderedList, // Ordered list
    VarStore,  // Define a buffer-style variable storage
    VarStoreNameValue, // Define a name/value style variable storage
    VarStoreEfi, // Define a UEFI variable style variable storage
    VarStoreDevice, // Specify the device path to use for variable storage
    Version, // Push the revision level of the UEFI Specification to which this Forms Processor is compliant
    End,     // Marks end of scope
    Match,   // Push TRUE if string matches a pattern
    Get,     // Return a stored value
    Set,     // Change a stored value
    Read,    // Provides a value for the current question or default
    Write,   // Change a value for the current question
    Equal,   // Push true if two expressions are equal
    NotEqual, // Push true if two expressions are not equal
    GreaterThan,
    GreaterEqual,
    LessThan,
    LessEqual,
    BitwiseAnd,
    BitwiseOr,
    BitwiseNot,
    ShiftLeft,
    ShiftRight,
    Add,
    Substract,
    Multiply,
    Divide,
    Modulo,
    RuleRef, // Evaluate a rule
    QuestionRef1,
    QuestionRef2,
    Uint8,
    Uint16,
    Uint32,
    Uint64,
    True,
    False,
    ToUint,
    ToString,
    ToBoolean,
    Mid,   // Extract portion of string or buffer
    Find,  // Find a string in a string
    Token, // Extract a delimited byte or character string from buffer or string
    StringRef1,
    StringRef2,
    Conditional, // Duplicate one of two expressions depending on result of the first expression
    QuestionRef3, // Push a question’s value from a different form
    Zero,
    One,
    Ones,         // Push a 0xFFFFFFFFFFFFFFFF
    Undefined,    // Push Undefined
    Length,       // Push length of buffer or string
    Dup,          // Duplicate top of expression stack
    This,         // Push the current question’s value
    Span,         // Return first matching/non-matching character in a string
    Value,        // Provide a value for a question
    Default,      // Provide a default value for a question
    DefaultStore, // Define a Default Type Declaration
    FormMap,      // Create a standards-map form
    Catenate,     // Push concatenated buffers or strings
    Guid,         // An extensible GUIDed op-code
    Security,     // Returns whether current user profile contains specified setup access privileges
    ModalTag,     // Specify current form is modal
    RefreshId,    // Establish an event group for refreshing a forms-based element
    WarningIf,    // Warning conditional
    Match2,       // Push TRUE if string matches a Regular Expression pattern
    Unknown(u8),
}

impl From<u8> for IfrOpcode {
    fn from(n: u8) -> IfrOpcode {
        match n {
            0x01 => IfrOpcode::Form,
            0x02 => IfrOpcode::Subtitle,
            0x03 => IfrOpcode::Text,
            0x04 => IfrOpcode::Image,
            0x05 => IfrOpcode::OneOf,
            0x06 => IfrOpcode::CheckBox,
            0x07 => IfrOpcode::Numeric,
            0x08 => IfrOpcode::Password,
            0x09 => IfrOpcode::OneOfOption,
            0x0A => IfrOpcode::SuppressIf,
            0x0B => IfrOpcode::Locked,
            0x0C => IfrOpcode::Action,
            0x0D => IfrOpcode::ResetButton,
            0x0E => IfrOpcode::FormSet,
            0x0F => IfrOpcode::Ref,
            0x10 => IfrOpcode::NoSubmitIf,
            0x11 => IfrOpcode::InconsistentIf,
            0x12 => IfrOpcode::EqIdVal,
            0x13 => IfrOpcode::EqIdId,
            0x14 => IfrOpcode::EqIdValList,
            0x15 => IfrOpcode::And,
            0x16 => IfrOpcode::Or,
            0x17 => IfrOpcode::Not,
            0x18 => IfrOpcode::Rule,
            0x19 => IfrOpcode::GrayOutIf,
            0x1A => IfrOpcode::Date,
            0x1B => IfrOpcode::Time,
            0x1C => IfrOpcode::String,
            0x1D => IfrOpcode::Refresh,
            0x1E => IfrOpcode::DisableIf,
            0x1F => IfrOpcode::Animation,
            0x20 => IfrOpcode::ToLower,
            0x21 => IfrOpcode::ToUpper,
            0x22 => IfrOpcode::Map,
            0x23 => IfrOpcode::OrderedList,
            0x24 => IfrOpcode::VarStore,
            0x25 => IfrOpcode::VarStoreNameValue,
            0x26 => IfrOpcode::VarStoreEfi,
            0x27 => IfrOpcode::VarStoreDevice,
            0x28 => IfrOpcode::Version,
            0x29 => IfrOpcode::End,
            0x2A => IfrOpcode::Match,
            0x2B => IfrOpcode::Get,
            0x2C => IfrOpcode::Set,
            0x2D => IfrOpcode::Read,
            0x2E => IfrOpcode::Write,
            0x2F => IfrOpcode::Equal,
            0x30 => IfrOpcode::NotEqual,
            0x31 => IfrOpcode::GreaterThan,
            0x32 => IfrOpcode::GreaterEqual,
            0x33 => IfrOpcode::LessThan,
            0x34 => IfrOpcode::LessEqual,
            0x35 => IfrOpcode::BitwiseAnd,
            0x36 => IfrOpcode::BitwiseOr,
            0x37 => IfrOpcode::BitwiseNot,
            0x38 => IfrOpcode::ShiftLeft,
            0x39 => IfrOpcode::ShiftRight,
            0x3A => IfrOpcode::Add,
            0x3B => IfrOpcode::Substract,
            0x3C => IfrOpcode::Multiply,
            0x3D => IfrOpcode::Divide,
            0x3E => IfrOpcode::Modulo,
            0x3F => IfrOpcode::RuleRef,
            0x40 => IfrOpcode::QuestionRef1,
            0x41 => IfrOpcode::QuestionRef2,
            0x42 => IfrOpcode::Uint8,
            0x43 => IfrOpcode::Uint16,
            0x44 => IfrOpcode::Uint32,
            0x45 => IfrOpcode::Uint64,
            0x46 => IfrOpcode::True,
            0x47 => IfrOpcode::False,
            0x48 => IfrOpcode::ToUint,
            0x49 => IfrOpcode::ToString,
            0x4A => IfrOpcode::ToBoolean,
            0x4B => IfrOpcode::Mid,
            0x4C => IfrOpcode::Find,
            0x4D => IfrOpcode::Token,
            0x4E => IfrOpcode::StringRef1,
            0x4F => IfrOpcode::StringRef2,
            0x50 => IfrOpcode::Conditional,
            0x51 => IfrOpcode::QuestionRef3,
            0x52 => IfrOpcode::Zero,
            0x53 => IfrOpcode::One,
            0x54 => IfrOpcode::Ones,
            0x55 => IfrOpcode::Undefined,
            0x56 => IfrOpcode::Length,
            0x57 => IfrOpcode::Dup,
            0x58 => IfrOpcode::This,
            0x59 => IfrOpcode::Span,
            0x5A => IfrOpcode::Value,
            0x5B => IfrOpcode::Default,
            0x5C => IfrOpcode::DefaultStore,
            0x5D => IfrOpcode::FormMap,
            0x5E => IfrOpcode::Catenate,
            0x5F => IfrOpcode::Guid,
            0x60 => IfrOpcode::Security,
            0x61 => IfrOpcode::ModalTag,
            0x62 => IfrOpcode::RefreshId,
            0x63 => IfrOpcode::WarningIf,
            0x64 => IfrOpcode::Match2,
            _ => IfrOpcode::Unknown(n),
        }
    }
}

impl Into<u8> for IfrOpcode {
    fn into(self) -> u8 {
        match self {
            IfrOpcode::Form => 0x01,
            IfrOpcode::Subtitle => 0x02,
            IfrOpcode::Text => 0x03,
            IfrOpcode::Image => 0x04,
            IfrOpcode::OneOf => 0x05,
            IfrOpcode::CheckBox => 0x06,
            IfrOpcode::Numeric => 0x07,
            IfrOpcode::Password => 0x08,
            IfrOpcode::OneOfOption => 0x09,
            IfrOpcode::SuppressIf => 0x0A,
            IfrOpcode::Locked => 0x0B,
            IfrOpcode::Action => 0x0C,
            IfrOpcode::ResetButton => 0x0D,
            IfrOpcode::FormSet => 0x0E,
            IfrOpcode::Ref => 0x0F,
            IfrOpcode::NoSubmitIf => 0x10,
            IfrOpcode::InconsistentIf => 0x11,
            IfrOpcode::EqIdVal => 0x12,
            IfrOpcode::EqIdId => 0x13,
            IfrOpcode::EqIdValList => 0x14,
            IfrOpcode::And => 0x15,
            IfrOpcode::Or => 0x16,
            IfrOpcode::Not => 0x17,
            IfrOpcode::Rule => 0x18,
            IfrOpcode::GrayOutIf => 0x19,
            IfrOpcode::Date => 0x1A,
            IfrOpcode::Time => 0x1B,
            IfrOpcode::String => 0x1C,
            IfrOpcode::Refresh => 0x1D,
            IfrOpcode::DisableIf => 0x1E,
            IfrOpcode::Animation => 0x1F,
            IfrOpcode::ToLower => 0x20,
            IfrOpcode::ToUpper => 0x21,
            IfrOpcode::Map => 0x22,
            IfrOpcode::OrderedList => 0x23,
            IfrOpcode::VarStore => 0x24,
            IfrOpcode::VarStoreNameValue => 0x25,
            IfrOpcode::VarStoreEfi => 0x26,
            IfrOpcode::VarStoreDevice => 0x27,
            IfrOpcode::Version => 0x28,
            IfrOpcode::End => 0x29,
            IfrOpcode::Match => 0x2A,
            IfrOpcode::Get => 0x2B,
            IfrOpcode::Set => 0x2C,
            IfrOpcode::Read => 0x2D,
            IfrOpcode::Write => 0x2E,
            IfrOpcode::Equal => 0x2F,
            IfrOpcode::NotEqual => 0x30,
            IfrOpcode::GreaterThan => 0x31,
            IfrOpcode::GreaterEqual => 0x32,
            IfrOpcode::LessThan => 0x33,
            IfrOpcode::LessEqual => 0x34,
            IfrOpcode::BitwiseAnd => 0x35,
            IfrOpcode::BitwiseOr => 0x36,
            IfrOpcode::BitwiseNot => 0x37,
            IfrOpcode::ShiftLeft => 0x38,
            IfrOpcode::ShiftRight => 0x39,
            IfrOpcode::Add => 0x3A,
            IfrOpcode::Substract => 0x3B,
            IfrOpcode::Multiply => 0x3C,
            IfrOpcode::Divide => 0x3D,
            IfrOpcode::Modulo => 0x3E,
            IfrOpcode::RuleRef => 0x3F,
            IfrOpcode::QuestionRef1 => 0x40,
            IfrOpcode::QuestionRef2 => 0x41,
            IfrOpcode::Uint8 => 0x42,
            IfrOpcode::Uint16 => 0x43,
            IfrOpcode::Uint32 => 0x44,
            IfrOpcode::Uint64 => 0x45,
            IfrOpcode::True => 0x46,
            IfrOpcode::False => 0x47,
            IfrOpcode::ToUint => 0x48,
            IfrOpcode::ToString => 0x49,
            IfrOpcode::ToBoolean => 0x4A,
            IfrOpcode::Mid => 0x4B,
            IfrOpcode::Find => 0x4C,
            IfrOpcode::Token => 0x4D,
            IfrOpcode::StringRef1 => 0x4E,
            IfrOpcode::StringRef2 => 0x4F,
            IfrOpcode::Conditional => 0x50,
            IfrOpcode::QuestionRef3 => 0x51,
            IfrOpcode::Zero => 0x52,
            IfrOpcode::One => 0x53,
            IfrOpcode::Ones => 0x54,
            IfrOpcode::Undefined => 0x55,
            IfrOpcode::Length => 0x56,
            IfrOpcode::Dup => 0x57,
            IfrOpcode::This => 0x58,
            IfrOpcode::Span => 0x59,
            IfrOpcode::Value => 0x5A,
            IfrOpcode::Default => 0x5B,
            IfrOpcode::DefaultStore => 0x5C,
            IfrOpcode::FormMap => 0x5D,
            IfrOpcode::Catenate => 0x5E,
            IfrOpcode::Guid => 0x5F,
            IfrOpcode::Security => 0x60,
            IfrOpcode::ModalTag => 0x61,
            IfrOpcode::RefreshId => 0x62,
            IfrOpcode::WarningIf => 0x63,
            IfrOpcode::Match2 => 0x64,
            IfrOpcode::Unknown(m) => m,
        }
    }
}

impl fmt::Display for IfrOperation<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let opcode: u8 = self.OpCode.into();
        let raw_len = 
        if self.ScopeStart {
            self.Length | 0x80
        } else {
            self.Length
        }; 

        write!(
            f,
            "{{ {:02X} {:02X}",
            opcode,
            raw_len,
        )
        .unwrap();

        if let Some(bytes) = self.Data {
            for byte in bytes {
                write!(
                    f,
                    " {:02X}",
                    byte
                )
                .unwrap();
            }
        }

        write!(f, " }}")
    }
}

//
//0x01 => IfrOpcode::Form
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrForm {
    pub FormId: u16,
    pub TitleStringId: u16,
}

pub fn ifr_form(input: &[u8]) -> IResult<&[u8], IfrForm> {
    do_parse!(
        input,
        fid: le_u16
            >> tsid: le_u16
            >> (IfrForm {
                FormId: fid,
                TitleStringId: tsid,
            })
    )
}

//
//0x02 => IfrOpcode::Subtitle
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrSubtitle {
    pub PromptStringId: u16,
    pub HelpStringId: u16,
    pub Flags: u8,
}

pub fn ifr_subtitle(input: &[u8]) -> IResult<&[u8], IfrSubtitle> {
    do_parse!(
        input,
        p: le_u16
            >> h: le_u16
            >> f: le_u8
            >> (IfrSubtitle {
                PromptStringId: p,
                HelpStringId: h,
                Flags: f,
            })
    )
}

//
//0x03 => IfrOpcode::Text
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrText {
    pub PromptStringId: u16,
    pub HelpStringId: u16,
    pub TextId: u16,
}

pub fn ifr_text(input: &[u8]) -> IResult<&[u8], IfrText> {
    do_parse!(
        input,
        p: le_u16
            >> h: le_u16
            >> t: le_u16
            >> (IfrText {
                PromptStringId: p,
                HelpStringId: h,
                TextId: t,
            })
    )
}

//
//0x04 => IfrOpcode::Image
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrImage {
    pub ImageId: u16,
}

pub fn ifr_image(input: &[u8]) -> IResult<&[u8], IfrImage> {
    do_parse!(input, iid: le_u16 >> (IfrImage { ImageId: iid }))
}

//
//0x05 => IfrOpcode::OneOf
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrOneOf {
    pub PromptStringId: u16,
    pub HelpStringId: u16,
    pub QuestionId: u16,
    pub VarStoreId: u16,
    pub VarStoreInfo: u16,
    pub QuestionFlags: u8,
    pub Flags: u8,
    pub MinMaxStepData8: [Option<u8>; 3],
    pub MinMaxStepData16: [Option<u16>; 3],
    pub MinMaxStepData32: [Option<u32>; 3],
    pub MinMaxStepData64: [Option<u64>; 3],
}

pub fn ifr_one_of(input: &[u8]) -> IResult<&[u8], IfrOneOf> {
    do_parse!(
        input,
        psid: le_u16
            >> hsid: le_u16
            >> qid: le_u16
            >> vsid: le_u16
            >> vsin: le_u16
            >> qf: le_u8
            >> f: le_u8
            >> mms8_0: cond!(f & 0x03 == 0, le_u8)
            >> mms8_1: cond!(f & 0x03 == 0, le_u8)
            >> mms8_2: cond!(f & 0x03 == 0, le_u8)
            >> mms16_0: cond!(f & 0x03 == 1, le_u16)
            >> mms16_1: cond!(f & 0x03 == 1, le_u16)
            >> mms16_2: cond!(f & 0x03 == 1, le_u16)
            >> mms32_0: cond!(f & 0x03 == 2, le_u32)
            >> mms32_1: cond!(f & 0x03 == 2, le_u32)
            >> mms32_2: cond!(f & 0x03 == 2, le_u32)
            >> mms64_0: cond!(f & 0x03 == 3, le_u64)
            >> mms64_1: cond!(f & 0x03 == 3, le_u64)
            >> mms64_2: cond!(f & 0x03 == 3, le_u64)
            >> (IfrOneOf {
                PromptStringId: psid,
                HelpStringId: hsid,
                QuestionId: qid,
                VarStoreId: vsid,
                VarStoreInfo: vsin,
                QuestionFlags: qf,
                Flags: f,
                MinMaxStepData8: [mms8_0, mms8_1, mms8_2],
                MinMaxStepData16: [mms16_0, mms16_1, mms16_2],
                MinMaxStepData32: [mms32_0, mms32_1, mms32_2],
                MinMaxStepData64: [mms64_0, mms64_1, mms64_2],
            })
    )
}

//
//0x06 => IfrOpcode::CheckBox
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrCheckBox {
    pub PromptStringId: u16,
    pub HelpStringId: u16,
    pub QuestionId: u16,
    pub VarStoreId: u16,
    pub VarStoreInfo: u16,
    pub QuestionFlags: u8,
    pub Flags: u8,
}

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum IfrDefaultFlags {
    Default = 0x01,
    MfgDefault = 0x02,
}

pub fn ifr_check_box(input: &[u8]) -> IResult<&[u8], IfrCheckBox> {
    do_parse!(
        input,
        psid: le_u16
            >> hsid: le_u16
            >> qid: le_u16
            >> vsid: le_u16
            >> vsin: le_u16
            >> qf: le_u8
            >> f: le_u8
            >> (IfrCheckBox {
                PromptStringId: psid,
                HelpStringId: hsid,
                QuestionId: qid,
                VarStoreId: vsid,
                VarStoreInfo: vsin,
                QuestionFlags: qf,
                Flags: f,
            })
    )
}

//
//0x07 => IfrOpcode::Numeric
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrNumeric {
    pub PromptStringId: u16,
    pub HelpStringId: u16,
    pub QuestionId: u16,
    pub VarStoreId: u16,
    pub VarStoreInfo: u16,
    pub QuestionFlags: u8,
    pub Flags: u8,
    pub MinMaxStepData8: [Option<u8>; 3],
    pub MinMaxStepData16: [Option<u16>; 3],
    pub MinMaxStepData32: [Option<u32>; 3],
    pub MinMaxStepData64: [Option<u64>; 3],
}

pub fn ifr_numeric(input: &[u8]) -> IResult<&[u8], IfrNumeric> {
    do_parse!(
        input,
        psid: le_u16
            >> hsid: le_u16
            >> qid: le_u16
            >> vsid: le_u16
            >> vsin: le_u16
            >> qf: le_u8
            >> f: le_u8
            >> mms8_0: cond!(f & 0x03 == 0, le_u8)
            >> mms8_1: cond!(f & 0x03 == 0, le_u8)
            >> mms8_2: cond!(f & 0x03 == 0, le_u8)
            >> mms16_0: cond!(f & 0x03 == 1, le_u16)
            >> mms16_1: cond!(f & 0x03 == 1, le_u16)
            >> mms16_2: cond!(f & 0x03 == 1, le_u16)
            >> mms32_0: cond!(f & 0x03 == 2, le_u32)
            >> mms32_1: cond!(f & 0x03 == 2, le_u32)
            >> mms32_2: cond!(f & 0x03 == 2, le_u32)
            >> mms64_0: cond!(f & 0x03 == 3, le_u64)
            >> mms64_1: cond!(f & 0x03 == 3, le_u64)
            >> mms64_2: cond!(f & 0x03 == 3, le_u64)
            >> (IfrNumeric {
                PromptStringId: psid,
                HelpStringId: hsid,
                QuestionId: qid,
                VarStoreId: vsid,
                VarStoreInfo: vsin,
                QuestionFlags: qf,
                Flags: f,
                MinMaxStepData8: [mms8_0, mms8_1, mms8_2],
                MinMaxStepData16: [mms16_0, mms16_1, mms16_2],
                MinMaxStepData32: [mms32_0, mms32_1, mms32_2],
                MinMaxStepData64: [mms64_0, mms64_1, mms64_2],
            })
    )
}

//
//0x08 => IfrOpcode::Password
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrPassword {
    pub PromptStringId: u16,
    pub HelpStringId: u16,
    pub QuestionId: u16,
    pub VarStoreId: u16,
    pub VarStoreInfo: u16,
    pub QuestionFlags: u8,
    pub MinSize: u16,
    pub MaxSize: u16,
}

pub fn ifr_password(input: &[u8]) -> IResult<&[u8], IfrPassword> {
    do_parse!(
        input,
        psid: le_u16
            >> hsid: le_u16
            >> qid: le_u16
            >> vsid: le_u16
            >> vsin: le_u16
            >> qf: le_u8
            >> ms: le_u16
            >> xs: le_u16
            >> (IfrPassword {
                PromptStringId: psid,
                HelpStringId: hsid,
                QuestionId: qid,
                VarStoreId: vsid,
                VarStoreInfo: vsin,
                QuestionFlags: qf,
                MinSize: ms,
                MaxSize: xs,
            })
    )
}

//
//0x09 => IfrOpcode::OneOfOption
//
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct HiiTime {
    pub Hour: u8,
    pub Minute: u8,
    pub Second: u8,
}

pub fn hii_time(input: &[u8]) -> IResult<&[u8], HiiTime> {
    do_parse!(
        input,
        h: le_u8
            >> m: le_u8
            >> s: le_u8
            >> (HiiTime {
                Hour: h,
                Minute: m,
                Second: s,
            })
    )
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct HiiDate {
    pub Year: u16,
    pub Month: u8,
    pub Day: u8,
}

pub fn hii_date(input: &[u8]) -> IResult<&[u8], HiiDate> {
    do_parse!(
        input,
        y: le_u16
            >> m: le_u8
            >> d: le_u8
            >> (HiiDate {
                Year: y,
                Month: m,
                Day: d,
            })
    )
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct HiiRef {
    pub QuestionId: Option<u16>,
    pub FormId: Option<u16>,
    pub FormSetGuid: Option<Guid>,
    pub DevicePathStringId: Option<u16>,
}

pub fn hii_ref(input: &[u8]) -> IResult<&[u8], HiiRef> {
    do_parse!(
        input,
        r: peek!(rest)
            >> qid: cond_with_error!(r.len() >= 2, le_u16)
            >> fid: cond_with_error!(r.len() >= 4, le_u16)
            >> fsg: cond_with_error!(r.len() >= 20, guid)
            >> dpid: cond_with_error!(r.len() >= 24, le_u16)
            >> (HiiRef {
                QuestionId: qid,
                FormId: fid,
                FormSetGuid: fsg,
                DevicePathStringId: dpid,
            })
    )
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub enum IfrTypeValue {
    NumSize8(u8),
    NumSize16(u16),
    NumSize32(u32),
    NumSize64(u64),
    Boolean(bool),
    Time(HiiTime),
    Date(HiiDate),
    String(u16),
    Other,
    Undefined,
    Action(u16),
    Buffer(Vec<u8>),
    Ref(HiiRef),
    Unknown(u8),
}

impl fmt::Display for IfrTypeValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            IfrTypeValue::NumSize8(x) => write!(f, "{}", x),
            IfrTypeValue::NumSize16(x) => write!(f, "{}", x),
            IfrTypeValue::NumSize32(x) => write!(f, "{}", x),
            IfrTypeValue::NumSize64(x) => write!(f, "{}", x),
            IfrTypeValue::Boolean(x) => write!(f, "{}", x),
            IfrTypeValue::Time(x) => write!(f, "{:02}:{:02}:{:02}", x.Hour, x.Minute, x.Second),
            IfrTypeValue::Date(x) => write!(f, "{:04}-{:02}-{:02}", x.Year, x.Month, x.Day),
            IfrTypeValue::String(x) => write!(f, "StringId: 0x{:X}", x),
            IfrTypeValue::Other => write!(f, "Other"),
            IfrTypeValue::Undefined => write!(f, "Undefined"),
            IfrTypeValue::Action(x) => write!(f, "Action: 0x{:X}", x),
            IfrTypeValue::Buffer(ref x) => write!(f, "Buffer: {:?}", x),
            IfrTypeValue::Ref(x) => {
                write!(f, "Ref").unwrap();
                if let Some(y) = x.QuestionId {
                    write!(f, " QuestionId: 0x{:X}", y).unwrap();
                }
                if let Some(y) = x.FormId {
                    write!(f, " FormId: 0x{:X}", y).unwrap();
                }
                if let Some(y) = x.FormSetGuid {
                    write!(f, " FormSetGuid: {}", y).unwrap();
                }
                if let Some(y) = x.DevicePathStringId {
                    write!(f, " DevicePathId: {}", y).unwrap();
                }
                write!(f, "")
            }
            IfrTypeValue::Unknown(x) => write!(f, "Unknown: {:?}", x),
        }
    }
}

fn ifr_type_value(input: &[u8]) -> IResult<&[u8], IfrTypeValue> {
    do_parse!(
        input,
        val: switch!(le_u8,
                0x00 => do_parse!(i: le_u8 >> ( IfrTypeValue::NumSize8(i) )) |
                0x01 => do_parse!(i: le_u16 >> ( IfrTypeValue::NumSize16(i) )) |
                0x02 => do_parse!(i: le_u32 >> ( IfrTypeValue::NumSize32(i) )) |
                0x03 => do_parse!(i: le_u64 >> ( IfrTypeValue::NumSize64(i) )) |
                0x04 => do_parse!(i: le_u8 >> ( IfrTypeValue::Boolean(i != 0) )) |
                0x05 => do_parse!(t: hii_time >> ( IfrTypeValue::Time(t) )) |
                0x06 => do_parse!(d: hii_date >> ( IfrTypeValue::Date(d) )) |
                0x07 => do_parse!(i: le_u16 >> ( IfrTypeValue::String(i) )) |
                0x08 => value!(IfrTypeValue::Other) |
                0x09 => value!(IfrTypeValue::Undefined) |
                0x0A => do_parse!(i: le_u16 >> ( IfrTypeValue::Action(i) )) |
                0x0B => do_parse!(b: rest >> ( IfrTypeValue::Buffer(b.to_vec()) )) |
                0x0C => do_parse!(r: hii_ref >> ( IfrTypeValue::Ref(r) )) |
                x => value!(IfrTypeValue::Unknown(x))
        ) >> rest
            >> (val)
    )
}

#[derive(Debug, PartialEq, Eq)]
pub struct IfrOneOfOption {
    pub OptionStringId: u16,
    pub Flags: u8,
    pub Value: IfrTypeValue,
}

pub fn ifr_one_of_option(input: &[u8]) -> IResult<&[u8], IfrOneOfOption> {
    do_parse!(
        input,
        osid: le_u16
            >> flgs: le_u8
            >> val: ifr_type_value
            >> (IfrOneOfOption {
                OptionStringId: osid,
                Flags: flgs,
                Value: val,
            })
    )
}

//0x0A => IfrOpcode::SuppressIf
//0x0B => IfrOpcode::Locked

//
//0x0C => IfrOpcode::Action
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrAction {
    pub PromptStringId: u16,
    pub HelpStringId: u16,
    pub QuestionId: u16,
    pub VarStoreId: u16,
    pub VarStoreInfo: u16,
    pub QuestionFlags: u8,
    pub ConfigStringId: Option<u16>,
}

pub fn ifr_action(input: &[u8]) -> IResult<&[u8], IfrAction> {
    do_parse!(
        input,
        psid: le_u16
            >> hsid: le_u16
            >> qid: le_u16
            >> vsid: le_u16
            >> vsin: le_u16
            >> qf: le_u8
            >> r: peek!(rest)
            >> csid: cond_with_error!(r.len() >= 2, le_u16)
            >> (IfrAction {
                PromptStringId: psid,
                HelpStringId: hsid,
                QuestionId: qid,
                VarStoreId: vsid,
                VarStoreInfo: vsin,
                QuestionFlags: qf,
                ConfigStringId: csid,
            })
    )
}

//
//0x0D => IfrOpcode::ResetButton
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrResetButton {
    pub PromptStringId: u16,
    pub HelpStringId: u16,
    pub DefaultId: u16,
}

pub fn ifr_reset_button(input: &[u8]) -> IResult<&[u8], IfrResetButton> {
    do_parse!(
        input,
        p: le_u16
            >> h: le_u16
            >> d: le_u16
            >> (IfrResetButton {
                PromptStringId: p,
                HelpStringId: h,
                DefaultId: d,
            })
    )
}

//
//0x0E => IfrOpcode::FormSet
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrFormSet {
    pub Guid: Guid,
    pub TitleStringId: u16,
    pub HelpStringId: u16,
    pub Flags: Option<u8>,
    pub ClassGuids: Option<Vec<Guid>>,
}

// Making Flags optional here is required because of some files found in the wild
pub fn ifr_form_set(input: &[u8]) -> IResult<&[u8], IfrFormSet> {
    do_parse!(
        input,
        mg: guid
            >> tsid: le_u16
            >> hsid: le_u16
            >> r: peek!(rest)
            >> flags: cond_with_error!(r.len() >= 1, le_u8)
            >> guids_count: cond_with_error!(r.len() >= 1, value!(flags.unwrap() & 0x03))
            >> guids: cond_with_error!(r.len() >= 1, count!(guid, guids_count.unwrap() as usize))
            >> (IfrFormSet {
                Guid: mg,
                TitleStringId: tsid,
                HelpStringId: hsid,
                Flags: flags,
                ClassGuids: guids,
            })
    )
}

//
//0x0F => IfrOpcode::Ref
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrRef {
    pub PromptStringId: u16,
    pub HelpStringId: u16,
    pub QuestionId: u16,
    pub VarStoreId: u16,
    pub VarStoreInfo: u16,
    pub QuestionFlags: u8,
    pub FormId: Option<u16>,
    pub RefQuestionId: Option<u16>,
    pub FormSetGuid: Option<Guid>,
    pub DevicePathId: Option<u16>,
}

pub fn ifr_ref(input: &[u8]) -> IResult<&[u8], IfrRef> {
    do_parse!(
        input,
        psid: le_u16
            >> hsid: le_u16
            >> qid: le_u16
            >> vsid: le_u16
            >> vsin: le_u16
            >> qf: le_u8
            >> r: peek!(rest)
            >> fid: cond_with_error!(r.len() >= 2, le_u16)
            >> rqid: cond_with_error!(r.len() >= 4, le_u16)
            >> fsg: cond_with_error!(r.len() >= 20, guid)
            >> dpid: cond_with_error!(r.len() >= 24, le_u16)
            >> (IfrRef {
                PromptStringId: psid,
                HelpStringId: hsid,
                QuestionId: qid,
                VarStoreId: vsid,
                VarStoreInfo: vsin,
                QuestionFlags: qf,
                FormId: fid,
                RefQuestionId: rqid,
                FormSetGuid: fsg,
                DevicePathId: dpid,
            })
    )
}

//
//0x10 => IfrOpcode::NoSubmitIf
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrNoSumbitIf {
    pub ErrorStringId: u16,
}

pub fn ifr_no_submit_if(input: &[u8]) -> IResult<&[u8], IfrNoSumbitIf> {
    do_parse!(
        input,
        esid: le_u16
            >> (IfrNoSumbitIf {
                ErrorStringId: esid,
            })
    )
}

//
//0x11 => IfrOpcode::InconsistentIf
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrInconsistentIf {
    pub ErrorStringId: u16,
}

pub fn ifr_inconsistent_if(input: &[u8]) -> IResult<&[u8], IfrInconsistentIf> {
    do_parse!(
        input,
        esid: le_u16
            >> (IfrInconsistentIf {
                ErrorStringId: esid,
            })
    )
}

//
//0x12 => IfrOpcode::EqIdVal
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrEqIdVal {
    pub QuestionId: u16,
    pub Value: u16,
}

pub fn ifr_eq_id_val(input: &[u8]) -> IResult<&[u8], IfrEqIdVal> {
    do_parse!(
        input,
        qid: le_u16
            >> val: le_u16
            >> (IfrEqIdVal {
                QuestionId: qid,
                Value: val,
            })
    )
}

//
//0x13 => IfrOpcode::EqIdId
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrEqIdId {
    pub QuestionId: u16,
    pub OtherQuestionId: u16,
}

pub fn ifr_eq_id_id(input: &[u8]) -> IResult<&[u8], IfrEqIdId> {
    do_parse!(
        input,
        qid: le_u16
            >> oid: le_u16
            >> (IfrEqIdId {
                QuestionId: qid,
                OtherQuestionId: oid,
            })
    )
}

//
//0x14 => IfrOpcode::EqIdValList
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrEqIdValList {
    pub QuestionId: u16,
    pub Values: Vec<u16>,
}

pub fn ifr_eq_id_val_list(input: &[u8]) -> IResult<&[u8], IfrEqIdValList> {
    do_parse!(
        input,
        qid: le_u16
            >> len: le_u16
            >> val: count!(le_u16, len as usize)
            >> (IfrEqIdValList {
                QuestionId: qid,
                Values: val,
            })
    )
}

//0x15 => IfrOpcode::And
//0x16 => IfrOpcode::Or
//0x17 => IfrOpcode::Not

//
//0x18 => IfrOpcode::Rule
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrRule {
    pub RuleId: u8,
}

pub fn ifr_rule(input: &[u8]) -> IResult<&[u8], IfrRule> {
    do_parse!(input, rid: le_u8 >> (IfrRule { RuleId: rid }))
}

//0x19 => IfrOpcode::GrayOutIf

//
//0x1A => IfrOpcode::Date
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrDate {
    pub PromptStringId: u16,
    pub HelpStringId: u16,
    pub QuestionId: u16,
    pub VarStoreId: u16,
    pub VarStoreInfo: u16,
    pub QuestionFlags: u8,
    pub Flags: u8,
}

pub fn ifr_date(input: &[u8]) -> IResult<&[u8], IfrDate> {
    do_parse!(
        input,
        psid: le_u16
            >> hsid: le_u16
            >> qid: le_u16
            >> vsid: le_u16
            >> vsin: le_u16
            >> qf: le_u8
            >> f: le_u8
            >> (IfrDate {
                PromptStringId: psid,
                HelpStringId: hsid,
                QuestionId: qid,
                VarStoreId: vsid,
                VarStoreInfo: vsin,
                QuestionFlags: qf,
                Flags: f,
            })
    )
}

//
//0x1B => IfrOpcode::Time
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrTime {
    pub PromptStringId: u16,
    pub HelpStringId: u16,
    pub QuestionId: u16,
    pub VarStoreId: u16,
    pub VarStoreInfo: u16,
    pub QuestionFlags: u8,
    pub Flags: u8,
}

pub fn ifr_time(input: &[u8]) -> IResult<&[u8], IfrTime> {
    do_parse!(
        input,
        psid: le_u16
            >> hsid: le_u16
            >> qid: le_u16
            >> vsid: le_u16
            >> vsin: le_u16
            >> qf: le_u8
            >> f: le_u8
            >> (IfrTime {
                PromptStringId: psid,
                HelpStringId: hsid,
                QuestionId: qid,
                VarStoreId: vsid,
                VarStoreInfo: vsin,
                QuestionFlags: qf,
                Flags: f,
            })
    )
}

//
//0x1C => IfrOpcode::String
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrString {
    pub PromptStringId: u16,
    pub HelpStringId: u16,
    pub QuestionId: u16,
    pub VarStoreId: u16,
    pub VarStoreInfo: u16,
    pub QuestionFlags: u8,
    pub MinSize: u8,
    pub MaxSize: u8,
    pub Flags: u8,
}

pub fn ifr_string(input: &[u8]) -> IResult<&[u8], IfrString> {
    do_parse!(
        input,
        psid: le_u16
            >> hsid: le_u16
            >> qid: le_u16
            >> vsid: le_u16
            >> vsin: le_u16
            >> qf: le_u8
            >> ms: le_u8
            >> xs: le_u8
            >> f: le_u8
            >> (IfrString {
                PromptStringId: psid,
                HelpStringId: hsid,
                QuestionId: qid,
                VarStoreId: vsid,
                VarStoreInfo: vsin,
                QuestionFlags: qf,
                MinSize: ms,
                MaxSize: xs,
                Flags: f
            })
    )
}

//
//0x1D => IfrOpcode::Refresh
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrRefresh {
    pub RefreshInterval: u8,
}

pub fn ifr_refresh(input: &[u8]) -> IResult<&[u8], IfrRefresh> {
    do_parse!(
        input,
        ri: le_u8
            >> (IfrRefresh {
                RefreshInterval: ri,
            })
    )
}

//0x1E => IfrOpcode::DisableIf

//
//0x1F => IfrOpcode::Animation
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrAnimation {
    pub AnimationId: u16,
}

pub fn ifr_animation(input: &[u8]) -> IResult<&[u8], IfrAnimation> {
    do_parse!(input, aid: le_u16 >> (IfrAnimation { AnimationId: aid }))
}

//0x20 => IfrOpcode::ToLower
//0x21 => IfrOpcode::ToUpper
//0x22 => IfrOpcode::Map

//
//0x23 => IfrOpcode::OrderedList
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrOrderedList {
    pub PromptStringId: u16,
    pub HelpStringId: u16,
    pub QuestionId: u16,
    pub VarStoreId: u16,
    pub VarStoreInfo: u16,
    pub QuestionFlags: u8,
    pub MaxContainers: u8,
    pub Flags: u8,
}

pub fn ifr_ordered_list(input: &[u8]) -> IResult<&[u8], IfrOrderedList> {
    do_parse!(
        input,
        psid: le_u16
            >> hsid: le_u16
            >> qid: le_u16
            >> vsid: le_u16
            >> vsin: le_u16
            >> qf: le_u8
            >> mc: le_u8
            >> f: le_u8
            >> (IfrOrderedList {
                PromptStringId: psid,
                HelpStringId: hsid,
                QuestionId: qid,
                VarStoreId: vsid,
                VarStoreInfo: vsin,
                QuestionFlags: qf,
                MaxContainers: mc,
                Flags: f,
            })
    )
}

//
//0x24 => IfrOpcode::VarStore
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrVarStore {
    pub Guid: Guid,
    pub VarStoreId: u16,
    pub Size: u16,
    pub Name: String,
}

pub fn ifr_var_store(input: &[u8]) -> IResult<&[u8], IfrVarStore> {
    do_parse!(
        input,
        g: guid
            >> vsid: le_u16
            >> size: le_u16
            >> name: take_until_and_consume!("\x00")
            >> (IfrVarStore {
                Guid: g,
                VarStoreId: vsid,
                Size: size,
                Name: String::from_utf8_lossy(&name).to_string(),
            })
    )
}

//
//0x25 => IfrOpcode::VarStoreNameValue
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrVarStoreNameValue {
    pub VarStoreId: u16,
    pub Guid: Guid,
}

pub fn ifr_var_store_name_value(input: &[u8]) -> IResult<&[u8], IfrVarStoreNameValue> {
    do_parse!(
        input,
        vsid: le_u16
            >> g: guid
            >> (IfrVarStoreNameValue {
                VarStoreId: vsid,
                Guid: g,
            })
    )
}

//
//0x26 => IfrOpcode::VarStoreEfi
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrVarStoreEfi {
    pub VarStoreId: u16,
    pub Guid: Guid,
    pub Attributes: u32,
    pub Size: Option<u16>,
    pub Name: Option<String>,
}

pub fn ifr_var_store_efi(input: &[u8]) -> IResult<&[u8], IfrVarStoreEfi> {
    do_parse!(
        input,
        r: peek!(rest)
            >> vsid: le_u16
            >> g: guid
            >> atr: le_u32
            >> size: cond_with_error!(r.len() >= 24, le_u16)
            >> name: cond_with_error!(r.len() >= 26, take_until_and_consume!("\x00"))
            >> (IfrVarStoreEfi {
                VarStoreId: vsid,
                Guid: g,
                Attributes: atr,
                Size: size,
                Name: match name {
                    Some(n) => Some(String::from_utf8_lossy(&n).to_string()),
                    None => None
                }
            })
    )
}

//
//0x27 => IfrOpcode::VarStoreDevice
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrVarStoreDevice {
    pub DevicePathStringId: u16,
}

pub fn ifr_var_store_device(input: &[u8]) -> IResult<&[u8], IfrVarStoreDevice> {
    do_parse!(
        input,
        dp: le_u16
            >> (IfrVarStoreDevice {
                DevicePathStringId: dp,
            })
    )
}

//0x28 => IfrOpcode::Version
//0x29 => IfrOpcode::End
//0x2A => IfrOpcode::Match

//
//0x2B => IfrOpcode::Get
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrGet {
    pub VarStoreId: u16,
    pub VarStoreInfo: u16,
    pub VarStoreType: u8,
}

pub fn ifr_get(input: &[u8]) -> IResult<&[u8], IfrGet> {
    do_parse!(
        input,
        vsid: le_u16
            >> vsin: le_u16
            >> vst: le_u8
            >> (IfrGet {
                VarStoreId: vsid,
                VarStoreInfo: vsin,
                VarStoreType: vst,
            })
    )
}

//
//0x2C => IfrOpcode::Set
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrSet {
    pub VarStoreId: u16,
    pub VarStoreInfo: u16,
    pub VarStoreType: u8,
}

pub fn ifr_set(input: &[u8]) -> IResult<&[u8], IfrSet> {
    do_parse!(
        input,
        vsid: le_u16
            >> vsin: le_u16
            >> vst: le_u8
            >> (IfrSet {
                VarStoreId: vsid,
                VarStoreInfo: vsin,
                VarStoreType: vst,
            })
    )
}

//
//0x3F => IfrOpcode::RuleRef
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrRuleRef {
    pub RuleId: u8,
}

pub fn ifr_rule_ref(input: &[u8]) -> IResult<&[u8], IfrRuleRef> {
    do_parse!(input, rid: le_u8 >> (IfrRuleRef { RuleId: rid }))
}

//
//0x40 => IfrOpcode::QuestionRef1
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrQuestionRef1 {
    pub QuestionId: u16,
}

pub fn ifr_question_ref_1(input: &[u8]) -> IResult<&[u8], IfrQuestionRef1> {
    do_parse!(input, qid: le_u16 >> (IfrQuestionRef1 { QuestionId: qid }))
}

//0x41 => IfrOpcode::QuestionRef2

//
//0x42 => IfrOpcode::Uint8
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrUint8 {
    pub Value: u8,
}

pub fn ifr_uint8(input: &[u8]) -> IResult<&[u8], IfrUint8> {
    do_parse!(input, u: le_u8 >> (IfrUint8 { Value: u }))
}

//
//0x43 => IfrOpcode::Uint16
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrUint16 {
    pub Value: u16,
}

pub fn ifr_uint16(input: &[u8]) -> IResult<&[u8], IfrUint16> {
    do_parse!(input, u: le_u16 >> (IfrUint16 { Value: u }))
}

//
//0x44 => IfrOpcode::Uint32
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrUint32 {
    pub Value: u32,
}

pub fn ifr_uint32(input: &[u8]) -> IResult<&[u8], IfrUint32> {
    do_parse!(input, u: le_u32 >> (IfrUint32 { Value: u }))
}

//
//0x45 => IfrOpcode::Uint64
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrUint64 {
    pub Value: u64,
}

pub fn ifr_uint64(input: &[u8]) -> IResult<&[u8], IfrUint64> {
    do_parse!(input, u: le_u64 >> (IfrUint64 { Value: u }))
}

//0x46 => IfrOpcode::True
//0x47 => IfrOpcode::False
//0x48 => IfrOpcode::ToUint

//
//0x49 => IfrOpcode::ToString
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrToString {
    pub Format: u8,
}

pub fn ifr_to_string(input: &[u8]) -> IResult<&[u8], IfrToString> {
    do_parse!(input, f: le_u8 >> (IfrToString { Format: f }))
}

//0x4A => IfrOpcode::ToBoolean
//0x4B => IfrOpcode::Mid

//
//0x4C => IfrOpcode::Find
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrFind {
    pub Format: u8,
}

pub fn ifr_find(input: &[u8]) -> IResult<&[u8], IfrFind> {
    do_parse!(input, f: le_u8 >> (IfrFind { Format: f }))
}

//0x4D => IfrOpcode::Token

//
//0x4E => IfrOpcode::StringRef1
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrStringRef1 {
    pub StringId: u16,
}

pub fn ifr_string_ref_1(input: &[u8]) -> IResult<&[u8], IfrStringRef1> {
    do_parse!(input, sid: le_u16 >> (IfrStringRef1 { StringId: sid }))
}

//0x4F => IfrOpcode::StringRef2
//0x50 => IfrOpcode::Conditional

//
//0x51 => IfrOpcode::QuestionRef3
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrQuestionRef3 {
    pub DevicePathId: Option<u16>,
    pub QuestionGuid: Option<Guid>,
}

pub fn ifr_question_ref_3(input: &[u8]) -> IResult<&[u8], IfrQuestionRef3> {
    do_parse!(
        input,
        r: peek!(rest)
            >> dpid: cond_with_error!(r.len() >= 2, le_u16)
            >> qg: cond_with_error!(r.len() >= 2 + 16, guid)
            >> (IfrQuestionRef3 {
                DevicePathId: dpid,
                QuestionGuid: qg,
            })
    )
}

//0x52 => IfrOpcode::Zero
//0x53 => IfrOpcode::One
//0x54 => IfrOpcode::Ones
//0x55 => IfrOpcode::Undefined
//0x56 => IfrOpcode::Length
//0x57 => IfrOpcode::Dup
//0x58 => IfrOpcode::This

//
//0x59 => IfrOpcode::Span
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrSpan {
    pub Flags: u8,
}

pub fn ifr_span(input: &[u8]) -> IResult<&[u8], IfrSpan> {
    do_parse!(input, f: le_u8 >> (IfrSpan { Flags: f }))
}

//0x5A => IfrOpcode::Value

//
//0x5B => IfrOpcode::Default
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrDefault {
    pub DefaultId: u16,
    pub Value: IfrTypeValue,
}

pub fn ifr_default(input: &[u8]) -> IResult<&[u8], IfrDefault> {
    do_parse!(
        input,
        did: le_u16
            >> val: ifr_type_value
            >> (IfrDefault {
                DefaultId: did,
                Value: val
            })
    )
}

//
//0x5C => IfrOpcode::DefaultStore
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrDefaultStore {
    pub NameStringId: u16,
    pub DefaultId: u16,
}

pub fn ifr_default_store(input: &[u8]) -> IResult<&[u8], IfrDefaultStore> {
    do_parse!(
        input,
        nsid: le_u16
            >> did: le_u16
            >> (IfrDefaultStore {
                NameStringId: nsid,
                DefaultId: did,
            })
    )
}

//
//0x5D => IfrOpcode::FormMap
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrFormMapMethod {
    pub MethodTitleId: u16,
    pub MethodIdentifier: Guid,
}

pub fn ifr_form_map_method(input: &[u8]) -> IResult<&[u8], IfrFormMapMethod> {
    do_parse!(
        input,
        mtl: le_u16
            >> mid: guid
            >> (IfrFormMapMethod {
                MethodTitleId: mtl,
                MethodIdentifier: mid,
            })
    )
}

#[derive(Debug, PartialEq, Eq)]
pub struct IfrFormMap {
    pub FormId: u16,
    pub Methods: Vec<IfrFormMapMethod>,
}

pub fn ifr_form_map(input: &[u8]) -> IResult<&[u8], IfrFormMap> {
    do_parse!(
        input,
        fid: le_u16
            >> mv: many1!(complete!(ifr_form_map_method))
            >> (IfrFormMap {
                FormId: fid,
                Methods: mv,
            })
    )
}

//0x5E => IfrOpcode::Catenate

//
//0x5F => IfrOpcode::Guid
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrGuid<'a> {
    pub Guid: Guid,
    pub Data: &'a [u8],
}

pub fn ifr_guid(input: &[u8]) -> IResult<&[u8], IfrGuid> {
    do_parse!(input, g: guid >> d: rest >> (IfrGuid { Guid: g, Data: d }))
}

// EDK2 GUID types
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum IfrEdk2ExtendOpCode {
    Label,
    Banner,
    Timeout,
    Class,
    SubClass,
    Unknown(u8),
}

impl From<u8> for IfrEdk2ExtendOpCode {
    fn from(n: u8) -> IfrEdk2ExtendOpCode {
        match n {
            0x00 => IfrEdk2ExtendOpCode::Label,
            0x01 => IfrEdk2ExtendOpCode::Banner,
            0x02 => IfrEdk2ExtendOpCode::Timeout,
            0x03 => IfrEdk2ExtendOpCode::Class,
            0x04 => IfrEdk2ExtendOpCode::SubClass,
            _ => IfrEdk2ExtendOpCode::Unknown(n),
        }
    }
}

pub const IFR_TIANO_GUID: Guid = Guid {
    data1: 0xf0b1735,
    data2: 0x87a0,
    data3: 0x4193,
    data4: [0xb2, 0x66, 0x53, 0x8c, 0x38, 0xaf, 0x48, 0xce],
};

#[derive(Debug, PartialEq, Eq)]
pub struct IfrGuidEdk2<'a> {
    pub ExtendedOpCode: IfrEdk2ExtendOpCode,
    pub Data: &'a [u8],
}

pub fn ifr_guid_edk2(input: &[u8]) -> IResult<&[u8], IfrGuidEdk2> {
    do_parse!(
        input,
        e: le_u8
            >> d: rest
            >> (IfrGuidEdk2 {
                ExtendedOpCode: IfrEdk2ExtendOpCode::from(e),
                Data: d
            })
    )
}
// Label, Timeout, Class and Subclass all have one u16 as Data

#[derive(Debug, PartialEq, Eq)]
pub struct IfrGuidEdk2Banner {
    pub TitleId: u16,
    pub LineNumber: u16,
    pub Alignment: u8,
}

pub fn ifr_guid_edk2_banner(input: &[u8]) -> IResult<&[u8], IfrGuidEdk2Banner> {
    do_parse!(
        input,
        t: le_u16
            >> l: le_u16
            >> a: le_u8
            >> (IfrGuidEdk2Banner {
                TitleId: t,
                LineNumber: l,
                Alignment: a
            })
    )
}

//EDK1 GUID types
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum IfrEdkExtendOpCode {
    OptionKey,
    VarEqName,
    Unknown(u8),
}

impl From<u8> for IfrEdkExtendOpCode {
    fn from(n: u8) -> IfrEdkExtendOpCode {
        match n {
            0x00 => IfrEdkExtendOpCode::OptionKey,
            0x01 => IfrEdkExtendOpCode::VarEqName,
            _ => IfrEdkExtendOpCode::Unknown(n),
        }
    }
}

pub const IFR_FRAMEWORK_GUID: Guid = Guid {
    data1: 0x31ca5d1a,
    data2: 0xd511,
    data3: 0x4931,
    data4: [0xb7, 0x82, 0xae, 0x6b, 0x2b, 0x17, 0x8c, 0xd7],
};

#[derive(Debug, PartialEq, Eq)]
pub struct IfrGuidEdk<'a> {
    pub ExtendedOpCode: IfrEdkExtendOpCode,
    pub QuestionId: u16,
    pub Data: &'a [u8],
}

pub fn ifr_guid_edk(input: &[u8]) -> IResult<&[u8], IfrGuidEdk> {
    do_parse!(
        input,
        e: le_u8
            >> t: le_u16
            >> d: rest
            >> (IfrGuidEdk {
                ExtendedOpCode: IfrEdkExtendOpCode::from(e),
                QuestionId: t,
                Data: d,
            })
    )
}
// VarEqName has NameId as Data

//
//0x60 => IfrOpcode::Security
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrSecurity {
    pub Guid: Guid,
}

pub fn ifr_security(input: &[u8]) -> IResult<&[u8], IfrSecurity> {
    do_parse!(input, g: guid >> (IfrSecurity { Guid: g }))
}

//0x61 => IfrOpcode::ModalTag

//
//0x62 => IfrOpcode::RefreshId
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrRefreshId {
    pub Guid: Guid,
}

pub fn ifr_refresh_id(input: &[u8]) -> IResult<&[u8], IfrRefreshId> {
    do_parse!(input, g: guid >> (IfrRefreshId { Guid: g }))
}

//
//0x63 => IfrOpcode::WarningIf
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrWarningIf {
    pub WarningStringId: u16,
    pub Timeout: u8,
}

pub fn ifr_warning_if(input: &[u8]) -> IResult<&[u8], IfrWarningIf> {
    do_parse!(
        input,
        wsid: le_u16
            >> t: le_u8
            >> (IfrWarningIf {
                WarningStringId: wsid,
                Timeout: t,
            })
    )
}

//
//0x64 => IfrOpcode::Match2
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrMatch2 {
    pub Guid: Guid,
}

pub fn ifr_match_2(input: &[u8]) -> IResult<&[u8], IfrMatch2> {
    do_parse!(input, g: guid >> (IfrMatch2 { Guid: g }))
}
