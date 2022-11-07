#![allow(non_snake_case)]
#![allow(deprecated)]

extern crate nom;

use nom::{le_u16, le_u32, le_u64, le_u8, IResult};
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
    pub Length: usize,
    pub Type: HiiPackageType,
    pub Data: Option<&'a [u8]>,
}

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum HiiPackageType {
    Font,
    String,
    Ifr,
    Keyboard,
    HandlePack,
    Variable,
    DevicePath,
    Unknown(u16),
}

impl From<u16> for HiiPackageType {
    fn from(n: u16) -> HiiPackageType {
        match n {
            0x01 => HiiPackageType::Font,
            0x02 => HiiPackageType::String,
            0x03 => HiiPackageType::Ifr,
            0x04 => HiiPackageType::Keyboard,
            0x05 => HiiPackageType::HandlePack,
            0x06 => HiiPackageType::Variable,
            0x07 => HiiPackageType::DevicePath,
            _ => HiiPackageType::Unknown(n),
        }
    }
}

pub fn hii_package(input: &[u8]) -> IResult<&[u8], HiiPackage> {
    do_parse!(
        input,
        len: le_u32
            >> typ: le_u16
            >> verify!(value!(len), |val: u32| val >= 6)
            >> data: cond_with_error!(len > 6, take!(len - 6))
            >> (HiiPackage {
                Length: len as usize,
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
        len: le_u32 >>
        typ: le_u16 >>
        verify!(value!(len), |val: u32| val > 0x06 + 0x20) >> // Total length of the package is sane
        verify!(value!(typ), |val: u16| val == 0x02) >> // Package type is 0x02 
        take!(len - 0x06 - 0x02) >> // Skip the rest up to the last 2 bytes
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
        len: le_u32 >>
        verify!(value!(len), |val: u32| val > 0x06) >> // Total length of the package is sane
        typ: le_u16 >>
        verify!(value!(typ), |val: u16| val == 0x03) >> // Package type is 0x03
        verify!(le_u8, |val: u8| val == 0x0E) >> // Must start with IfrOpCode::FormSet
        take!(len - 0x06 - 0x01 - 0x02) >> // Skip the rest up to the last 2 bytes
        verify!(le_u16, |val: u16| val == 0x020D) >> // Last 2 bytes must be IfrOpCode::EndFormSet
        ( len as usize )
    )
}

//
// HII string package
//
#[derive(Debug, PartialEq, Eq)]
pub struct HiiStringPackage {
    pub LanguageNameStringOffset: u32,
    pub PrintableLanguageNameOffset: u32,
    pub NumStringPointers: u32,
    pub Attributes: u32,
    pub StringPointers: Vec<u32>,
    pub Strings: Vec<String>,
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

pub fn string_ucs2(input: &[u8]) -> IResult<&[u8], String> {
    do_parse!(
        input,
        s: ucs2_string >> (String::from_utf16_lossy(&s[..s.len() - 1]))
    )
}

pub fn hii_string_package(input: &[u8]) -> IResult<&[u8], HiiStringPackage> {
    do_parse!(
        input,
        lnso: le_u32
            >> plno: le_u32
            >> nsp: le_u32
            >> attr: le_u32
            >> sp: count!(le_u32, nsp as usize)
            >> s: count!(string_ucs2, nsp as usize)
            >> (HiiStringPackage {
                LanguageNameStringOffset: lnso,
                PrintableLanguageNameOffset: plno,
                NumStringPointers: nsp,
                Attributes: attr,
                StringPointers: sp,
                Strings: s,
            })
    )
}

//
// HII form package
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrOperation<'a> {
    pub OpCode: IfrOpcode,
    pub Length: u8,
    pub Data: Option<&'a [u8]>,
}

pub fn ifr_operation(input: &[u8]) -> IResult<&[u8], IfrOperation> {
    do_parse!(
        input,
        opcode: le_u8
            >> len: le_u8
            >> verify!(value!(len), |val: u8| val >= 2)
            >> data: cond_with_error!(len > 2, take!((len - 2) as usize))
            >> (IfrOperation {
                OpCode: IfrOpcode::from(opcode),
                Length: len,
                Data: data
            })
    )
}

pub fn ifr_operations(input: &[u8]) -> IResult<&[u8], Vec<IfrOperation>> {
    do_parse!(input, v: many1!(complete!(ifr_operation)) >> (v))
}

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum IfrOpcode {
    Form,
    Subtitle,
    Text,
    Graphic,
    OneOf,
    CheckBox,
    Numeric,
    Password,
    OneOfOption,
    SuppressIf,
    EndForm,
    Hidden,
    EndFormSet,
    FormSet,
    Ref,
    End,
    InconsistentIf,
    EqIdVal,
    EqIdId,
    EqIdList,
    And,
    Or,
    Not,
    EndIf,
    GrayOutIf,
    Date,
    Time,
    String,
    Label,
    SaveDefaults,
    RestoreDefaults,
    Banner,
    Inventory,
    EqVarVal,
    OrderedList,
    VarStore,
    VarStoreSelect,
    VarStoreSelectPair,
    True,
    False,
    Greater,
    GreaterEqual,
    OemDefined,
    Oem,
    NvAccessCommand,
    Unknown(u8),
}

impl From<u8> for IfrOpcode {
    fn from(n: u8) -> IfrOpcode {
        match n {
            0x01 => IfrOpcode::Form,
            0x02 => IfrOpcode::Subtitle,
            0x03 => IfrOpcode::Text,
            0x04 => IfrOpcode::Graphic,
            0x05 => IfrOpcode::OneOf,
            0x06 => IfrOpcode::CheckBox,
            0x07 => IfrOpcode::Numeric,
            0x08 => IfrOpcode::Password,
            0x09 => IfrOpcode::OneOfOption,
            0x0A => IfrOpcode::SuppressIf,
            0x0B => IfrOpcode::EndForm,
            0x0C => IfrOpcode::Hidden,
            0x0D => IfrOpcode::EndFormSet,
            0x0E => IfrOpcode::FormSet,
            0x0F => IfrOpcode::Ref,
            0x10 => IfrOpcode::End,
            0x11 => IfrOpcode::InconsistentIf,
            0x12 => IfrOpcode::EqIdVal,
            0x13 => IfrOpcode::EqIdId,
            0x14 => IfrOpcode::EqIdList,
            0x15 => IfrOpcode::And,
            0x16 => IfrOpcode::Or,
            0x17 => IfrOpcode::Not,
            0x18 => IfrOpcode::EndIf,
            0x19 => IfrOpcode::GrayOutIf,
            0x1A => IfrOpcode::Date,
            0x1B => IfrOpcode::Time,
            0x1C => IfrOpcode::String,
            0x1D => IfrOpcode::Label,
            0x1E => IfrOpcode::SaveDefaults,
            0x1F => IfrOpcode::RestoreDefaults,
            0x20 => IfrOpcode::Banner,
            0x21 => IfrOpcode::Inventory,
            0x22 => IfrOpcode::EqVarVal,
            0x23 => IfrOpcode::OrderedList,
            0x24 => IfrOpcode::VarStore,
            0x25 => IfrOpcode::VarStoreSelect,
            0x26 => IfrOpcode::VarStoreSelectPair,
            0x27 => IfrOpcode::True,
            0x28 => IfrOpcode::False,
            0x29 => IfrOpcode::Greater,
            0x2A => IfrOpcode::GreaterEqual,
            0x2B => IfrOpcode::OemDefined,
            0xFE => IfrOpcode::Oem,
            0xFF => IfrOpcode::NvAccessCommand,
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
            IfrOpcode::Graphic => 0x04,
            IfrOpcode::OneOf => 0x05,
            IfrOpcode::CheckBox => 0x06,
            IfrOpcode::Numeric => 0x07,
            IfrOpcode::Password => 0x08,
            IfrOpcode::OneOfOption => 0x09,
            IfrOpcode::SuppressIf => 0x0A,
            IfrOpcode::EndForm => 0x0B,
            IfrOpcode::Hidden => 0x0C,
            IfrOpcode::EndFormSet => 0x0D,
            IfrOpcode::FormSet => 0x0E,
            IfrOpcode::Ref => 0x0F,
            IfrOpcode::End => 0x10,
            IfrOpcode::InconsistentIf => 0x11,
            IfrOpcode::EqIdVal => 0x12,
            IfrOpcode::EqIdId => 0x13,
            IfrOpcode::EqIdList => 0x14,
            IfrOpcode::And => 0x15,
            IfrOpcode::Or => 0x16,
            IfrOpcode::Not => 0x17,
            IfrOpcode::EndIf => 0x18,
            IfrOpcode::GrayOutIf => 0x19,
            IfrOpcode::Date => 0x1A,
            IfrOpcode::Time => 0x1B,
            IfrOpcode::String => 0x1C,
            IfrOpcode::Label => 0x1D,
            IfrOpcode::SaveDefaults => 0x1E,
            IfrOpcode::RestoreDefaults => 0x1F,
            IfrOpcode::Banner => 0x20,
            IfrOpcode::Inventory => 0x21,
            IfrOpcode::EqVarVal => 0x22,
            IfrOpcode::OrderedList => 0x23,
            IfrOpcode::VarStore => 0x24,
            IfrOpcode::VarStoreSelect => 0x25,
            IfrOpcode::VarStoreSelectPair => 0x26,
            IfrOpcode::True => 0x27,
            IfrOpcode::False => 0x28,
            IfrOpcode::Greater => 0x29,
            IfrOpcode::GreaterEqual => 0x2A,
            IfrOpcode::OemDefined => 0x2B,
            IfrOpcode::Oem => 0xFE,
            IfrOpcode::NvAccessCommand => 0xFF,
            IfrOpcode::Unknown(m) => m,
        }
    }
}

impl fmt::Display for IfrOperation<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let opcode: u8 = self.OpCode.into();

        write!(
            f,
            "{{ {:02X} {:02X}",
            opcode,
            self.Length,
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
    pub SubtitleStringId: u16,
}

pub fn ifr_subtitle(input: &[u8]) -> IResult<&[u8], IfrSubtitle> {
    do_parse!(
        input,
        s: le_u16
            >> (IfrSubtitle {
                SubtitleStringId: s,
            })
    )
}

//
//0x03 => IfrOpcode::Text
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrText {
    pub HelpStringId: u16,
    pub TextStringId: u16,
    pub TextTwoStringId: u16,
    pub Flags: u8,
    pub Key: u16,
}

pub fn ifr_text(input: &[u8]) -> IResult<&[u8], IfrText> {
    do_parse!(
        input,
        h: le_u16
            >> t: le_u16
            >> t2: le_u16
            >> f: le_u8
            >> k: le_u16
            >> (IfrText {
                HelpStringId: h,
                TextStringId: t,
                TextTwoStringId: t2,
                Flags: f,
                Key: k,
            })
    )
}

//0x04 => IfrOpcode::Graphic

//
//0x05 => IfrOpcode::OneOf
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrOneOf {
    pub QuestionId: u16,
    pub Width: u8,
    pub PromptStringId: u16,
    pub HelpStringId: u16,
}

pub fn ifr_one_of(input: &[u8]) -> IResult<&[u8], IfrOneOf> {
    do_parse!(
        input,
        qid: le_u16
            >> w: le_u8
            >> psid: le_u16
            >> hsid: le_u16
            >> (IfrOneOf {
                QuestionId: qid,
                Width: w,
                PromptStringId: psid,
                HelpStringId: hsid,
            })
    )
}

//
//0x06 => IfrOpcode::CheckBox
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrCheckBox {
    pub QuestionId: u16,
    pub Width: u8,
    pub PromptStringId: u16,
    pub HelpStringId: u16,
    pub Flags: u8,
    pub Key: u16,
}

pub fn ifr_check_box(input: &[u8]) -> IResult<&[u8], IfrCheckBox> {
    do_parse!(
        input,
        qid: le_u16
            >> w: le_u8
            >> psid: le_u16
            >> hsid: le_u16
            >> f: le_u8
            >> k: le_u16
            >> (IfrCheckBox {
                QuestionId: qid,
                Width: w,
                PromptStringId: psid,
                HelpStringId: hsid,
                Flags: f,
                Key: k,
            })
    )
}

//
//0x07 => IfrOpcode::Numeric
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrNumeric {
    pub QuestionId: u16,
    pub Width: u8,
    pub PromptStringId: u16,
    pub HelpStringId: u16,
    pub Flags: u8,
    pub Key: u16,
    pub Min: u16,
    pub Max: u16,
    pub Step: u16,
    pub Default: u16,
}

pub fn ifr_numeric(input: &[u8]) -> IResult<&[u8], IfrNumeric> {
    do_parse!(
        input,
        qid: le_u16
            >> w: le_u8
            >> psid: le_u16
            >> hsid: le_u16
            >> f: le_u8
            >> k: le_u16
            >> min: le_u16
            >> max: le_u16
            >> step: le_u16
            >> def: le_u16
            >> (IfrNumeric {
                QuestionId: qid,
                Width: w,
                PromptStringId: psid,
                HelpStringId: hsid,
                Flags: f,
                Key: k,
                Min: min,
                Max: max,
                Step: step,
                Default: def,
            })
    )
}

//
//0x08 => IfrOpcode::Password
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrPassword {
    pub QuestionId: u16,
    pub Width: u8,
    pub PromptStringId: u16,
    pub HelpStringId: u16,
    pub Flags: u8,
    pub Key: u16,
    pub MinSize: u8,
    pub MaxSize: u8,
    pub Encoding: u16,
}

pub fn ifr_password(input: &[u8]) -> IResult<&[u8], IfrPassword> {
    do_parse!(
        input,
        qid: le_u16
            >> w: le_u8
            >> psid: le_u16
            >> hsid: le_u16
            >> f: le_u8
            >> k: le_u16
            >> ms: le_u8
            >> xs: le_u8
            >> e: le_u16
            >> (IfrPassword {
                QuestionId: qid,
                Width: w,
                PromptStringId: psid,
                HelpStringId: hsid,
                Flags: f,
                Key: k,
                MinSize: ms,
                MaxSize: xs,
                Encoding: e,
            })
    )
}

//
//0x09 => IfrOpcode::OneOfOption
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrOneOfOption {
    pub OptionStringId: u16,
    pub Value: u16,
    pub Flags: u8,
    pub Key: u16,
}

pub fn ifr_one_of_option(input: &[u8]) -> IResult<&[u8], IfrOneOfOption> {
    do_parse!(
        input,
        osid: le_u16
            >> val: le_u16
            >> f: le_u8
            >> k: le_u16
            >> (IfrOneOfOption {
                OptionStringId: osid,
                Value: val,
                Flags: f,
                Key: k,
            })
    )
}

//
//0x0A => IfrOpcode::SuppressIf
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrSuppressIf {
    pub Flags: u8,
}

pub fn ifr_supress_if(input: &[u8]) -> IResult<&[u8], IfrSuppressIf> {
    do_parse!(input, f: le_u8 >> (IfrSuppressIf { Flags: f }))
}

//0x0B => IfrOpcode::EndForm

//
//0x0C => IfrOpcode::Hidden
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrHidden {
    pub Value: u16,
    pub Key: u16,
}

pub fn ifr_hidden(input: &[u8]) -> IResult<&[u8], IfrHidden> {
    do_parse!(
        input,
        val: le_u16 >> k: le_u16 >> (IfrHidden { Value: val, Key: k })
    )
}

//0x0D => IfrOpcode::EndFormSet

//
//0x0E => IfrOpcode::FormSet
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrFormSet {
    pub Guid: Guid,
    pub TitleStringId: u16,
    pub HelpStringId: u16,
    pub CallbackHandle: u64,
    pub Class: u16,
    pub SubClass: u16,
    pub NvDataSize: u16,
}

pub fn ifr_form_set(input: &[u8]) -> IResult<&[u8], IfrFormSet> {
    do_parse!(
        input,
        mg: guid
            >> tsid: le_u16
            >> hsid: le_u16
            >> ch: le_u64
            >> c: le_u16
            >> sc: le_u16
            >> nvds: le_u16
            >> (IfrFormSet {
                Guid: mg,
                TitleStringId: tsid,
                HelpStringId: hsid,
                CallbackHandle: ch,
                Class: c,
                SubClass: sc,
                NvDataSize: nvds,
            })
    )
}

//
//0x0F => IfrOpcode::Ref
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrRef {
    pub FormId: u16,
    pub PromptStringId: u16,
    pub HelpStringId: u16,
    pub Flags: u8,
    pub Key: u16,
}

pub fn ifr_ref(input: &[u8]) -> IResult<&[u8], IfrRef> {
    do_parse!(
        input,
        fid: le_u16
            >> psid: le_u16
            >> hsid: le_u16
            >> f: le_u8
            >> k: le_u16
            >> (IfrRef {
                FormId: fid,
                PromptStringId: psid,
                HelpStringId: hsid,
                Flags: f,
                Key: k,
            })
    )
}

//0x10 => IfrOpcode::End

//
//0x11 => IfrOpcode::InconsistentIf
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrInconsistentIf {
    pub PopupStringId: u16,
    pub Flags: u8,
}

pub fn ifr_inconsistent_if(input: &[u8]) -> IResult<&[u8], IfrInconsistentIf> {
    do_parse!(
        input,
        psid: le_u16
            >> f: le_u8
            >> (IfrInconsistentIf {
                PopupStringId: psid,
                Flags: f,
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
    pub QuestionId1: u16,
    pub QuestionId2: u16,
}

pub fn ifr_eq_id_id(input: &[u8]) -> IResult<&[u8], IfrEqIdId> {
    do_parse!(
        input,
        qid1: le_u16
            >> qid2: le_u16
            >> (IfrEqIdId {
                QuestionId1: qid1,
                QuestionId2: qid2,
            })
    )
}

//
//0x14 => IfrOpcode::EqIdList
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrEqIdList {
    pub QuestionId: u16,
    pub Width: u8,
    pub ListLength: u16,
    pub List: Vec<u16>,
}

pub fn ifr_eq_id_list(input: &[u8]) -> IResult<&[u8], IfrEqIdList> {
    do_parse!(
        input,
        qid: le_u16
            >> w: le_u8
            >> len: le_u16
            >> l: count!(le_u16, len as usize)
            >> (IfrEqIdList {
                QuestionId: qid,
                Width: w,
                ListLength: len,
                List: l,
            })
    )
}

//0x15 => IfrOpcode::And
//0x16 => IfrOpcode::Or
//0x17 => IfrOpcode::Not
//0x18 => IfrOpcode::EndIf

//
//0x19 => IfrOpcode::GrayOutIf
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrGrayOutIf {
    pub Flags: u8,
}

pub fn ifr_grayout_if(input: &[u8]) -> IResult<&[u8], IfrGrayOutIf> {
    do_parse!(input, f: le_u8 >> (IfrGrayOutIf { Flags: f }))
}

//
//0x1A => IfrOpcode::Date
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrDate {
    pub QuestionId: u16,
    pub Width: u8,
    pub PromptStringId: u16,
    pub HelpStringId: u16,
    pub Flags: u8,
    pub Key: u16,
    pub Min: u16,
    pub Max: u16,
    pub Step: u16,
    pub Default: u16,
}

pub fn ifr_date(input: &[u8]) -> IResult<&[u8], IfrDate> {
    do_parse!(
        input,
        qid: le_u16
            >> w: le_u8
            >> psid: le_u16
            >> hsid: le_u16
            >> f: le_u8
            >> k: le_u16
            >> min: le_u16
            >> max: le_u16
            >> step: le_u16
            >> def: le_u16
            >> (IfrDate {
                QuestionId: qid,
                Width: w,
                PromptStringId: psid,
                HelpStringId: hsid,
                Flags: f,
                Key: k,
                Min: min,
                Max: max,
                Step: step,
                Default: def,
            })
    )
}

//
//0x1B => IfrOpcode::Time
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrTime {
    pub QuestionId: u16,
    pub Width: u8,
    pub PromptStringId: u16,
    pub HelpStringId: u16,
    pub Flags: u8,
    pub Key: u16,
    pub Min: u16,
    pub Max: u16,
    pub Step: u16,
    pub Default: u16,
}

pub fn ifr_time(input: &[u8]) -> IResult<&[u8], IfrTime> {
    do_parse!(
        input,
        qid: le_u16
            >> w: le_u8
            >> psid: le_u16
            >> hsid: le_u16
            >> f: le_u8
            >> k: le_u16
            >> min: le_u16
            >> max: le_u16
            >> step: le_u16
            >> def: le_u16
            >> (IfrTime {
                QuestionId: qid,
                Width: w,
                PromptStringId: psid,
                HelpStringId: hsid,
                Flags: f,
                Key: k,
                Min: min,
                Max: max,
                Step: step,
                Default: def,
            })
    )
}

//
//0x1C => IfrOpcode::String
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrString {
    pub QuestionId: u16,
    pub Width: u8,
    pub PromptStringId: u16,
    pub HelpStringId: u16,
    pub Flags: u8,
    pub Key: u16,
    pub MinSize: u8,
    pub MaxSize: u8,
}

pub fn ifr_string(input: &[u8]) -> IResult<&[u8], IfrString> {
    do_parse!(
        input,
        qid: le_u16
            >> w: le_u8
            >> psid: le_u16
            >> hsid: le_u16
            >> f: le_u8
            >> k: le_u16
            >> ms: le_u8
            >> xs: le_u8
            >> (IfrString {
                QuestionId: qid,
                Width: w,
                PromptStringId: psid,
                HelpStringId: hsid,
                Flags: f,
                Key: k,
                MinSize: ms,
                MaxSize: xs,
            })
    )
}

//
//0x1D => IfrOpcode::Label
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrLabel {
    pub LabelId: u16,
}

pub fn ifr_label(input: &[u8]) -> IResult<&[u8], IfrLabel> {
    do_parse!(input, l: le_u16 >> (IfrLabel { LabelId: l }))
}

//
//0x1E => IfrOpcode::SaveDefaults
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrSaveDefaults {
    pub FormId: u16,
    pub PromptStringId: u16,
    pub HelpStringId: u16,
    pub Flags: u8,
    pub Key: u16,
}

pub fn ifr_save_defaults(input: &[u8]) -> IResult<&[u8], IfrSaveDefaults> {
    do_parse!(
        input,
        fid: le_u16
            >> psid: le_u16
            >> hsid: le_u16
            >> f: le_u8
            >> k: le_u16
            >> (IfrSaveDefaults {
                FormId: fid,
                PromptStringId: psid,
                HelpStringId: hsid,
                Flags: f,
                Key: k,
            })
    )
}

//
//0x1F => IfrOpcode::RestoreDefaults
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrRestoreDefaults {
    pub FormId: u16,
    pub PromptStringId: u16,
    pub HelpStringId: u16,
    pub Flags: u8,
    pub Key: u16,
}

pub fn ifr_restore_defaults(input: &[u8]) -> IResult<&[u8], IfrRestoreDefaults> {
    do_parse!(
        input,
        fid: le_u16
            >> psid: le_u16
            >> hsid: le_u16
            >> f: le_u8
            >> k: le_u16
            >> (IfrRestoreDefaults {
                FormId: fid,
                PromptStringId: psid,
                HelpStringId: hsid,
                Flags: f,
                Key: k,
            })
    )
}

//
//0x20 => IfrOpcode::Banner
//
pub struct IfrBanner {
    pub TitleStringId: u16,
    pub LineNumber: u16,
    pub Alignment: u8,
}

pub fn ifr_banner(input: &[u8]) -> IResult<&[u8], IfrBanner> {
    do_parse!(
        input,
        tsid: le_u16
            >> ln: le_u16
            >> a: le_u8
            >> (IfrBanner {
                TitleStringId: tsid,
                LineNumber: ln,
                Alignment: a,
            })
    )
}

//
//0x21 => IfrOpcode::Inventory
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrInventory {
    pub HelpStringId: u16,
    pub TextStringId: u16,
    pub TextTwoStringId: u16,
}

pub fn ifr_inventory(input: &[u8]) -> IResult<&[u8], IfrInventory> {
    do_parse!(
        input,
        h: le_u16
            >> t: le_u16
            >> t2: le_u16
            >> (IfrInventory {
                HelpStringId: h,
                TextStringId: t,
                TextTwoStringId: t2,
            })
    )
}

//
//0x22 => IfrOpcode::EqVarVal
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrEqVarVal {
    pub VariableId: u16,
    pub Value: u16,
}

pub fn ifr_eq_var_val(input: &[u8]) -> IResult<&[u8], IfrEqVarVal> {
    do_parse!(
        input,
        var: le_u16
            >> val: le_u16
            >> (IfrEqVarVal {
                VariableId: var,
                Value: val,
            })
    )
}

//
//0x23 => IfrOpcode::OrderedList
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrOrderedList {
    pub QuestionId: u16,
    pub MaxEntries: u8,
    pub PromptStringId: u16,
    pub HelpStringId: u16,
}

pub fn ifr_ordered_list(input: &[u8]) -> IResult<&[u8], IfrOrderedList> {
    do_parse!(
        input,
        qid: le_u16
            >> me: le_u8
            >> psid: le_u16
            >> hsid: le_u16
            >> (IfrOrderedList {
                QuestionId: qid,
                MaxEntries: me,
                PromptStringId: psid,
                HelpStringId: hsid,
            })
    )
}

//
//0x24 => IfrOpcode::VarStore
//
named!(
    ascii_string<Vec<u8>>,
    map!(many_till!(le_u8, verify!(le_u8, |n: u8| n == 0)), |(
        mut v,
        n,
    )| {
        v.push(n);
        v
    })
);

pub fn string_ascii(input: &[u8]) -> IResult<&[u8], String> {
    do_parse!(
        input,
        s: ascii_string >> (String::from_utf8_lossy(&s[..s.len() - 1]).to_string())
    )
}

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
            >> name: string_ascii
            >> (IfrVarStore {
                Guid: g,
                VarStoreId: vsid,
                Size: size,
                Name: name,
            })
    )
}

//
//0x25 => IfrOpcode::VarStoreSelect
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrVarStoreSelect {
    pub VarStoreId: u16,
}

pub fn ifr_var_store_select(input: &[u8]) -> IResult<&[u8], IfrVarStoreSelect> {
    do_parse!(
        input,
        vsid: le_u16 >> (IfrVarStoreSelect { VarStoreId: vsid })
    )
}

//
//0x26 => IfrOpcode::VarStoreSelectPair
//
#[derive(Debug, PartialEq, Eq)]
pub struct IfrVarStoreSelectPair {
    pub VarStoreId: u16,
    pub SecondaryVarStoreId: u16,
}

pub fn ifr_var_store_select_pair(input: &[u8]) -> IResult<&[u8], IfrVarStoreSelectPair> {
    do_parse!(
        input,
        vsid: le_u16
            >> vsid2: le_u16
            >> (IfrVarStoreSelectPair {
                VarStoreId: vsid,
                SecondaryVarStoreId: vsid2,
            })
    )
}

//0x27 => IfrOpcode::True
//0x28 => IfrOpcode::False
//0x29 => IfrOpcode::Greater
//0x2A => IfrOpcode::GreaterEqual
//0x2B => IfrOpcode::OemDefined
//0xFE => IfrOpcode::Oem
//0xFF => IfrOpcode::NvAccessCommand
