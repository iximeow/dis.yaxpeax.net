use fastly::http::{header, Method, StatusCode};
use fastly::{Error, Request, Response};
use std::time::Instant;

#[fastly::main]
fn main(req: Request) -> Result<Response, Error> {
    // Filter request methods...
    match req.get_method() {
        // Allow GET and HEAD requests.
        &Method::GET | &Method::HEAD => (),
        // Deny anything else.
        _ => {
            return Ok(Response::from_status(StatusCode::METHOD_NOT_ALLOWED)
                .with_header(header::ALLOW, "GET, HEAD")
                .with_body_text_plain(""))
        }
    }

    let (status, resp) = handle_req(&req);

    Ok(Response::from_status(status).with_body_str(&resp).with_content_type(fastly::mime::TEXT_HTML))
}

const USAGE_STRING: &'static str = "
<html><body><pre>
usage: `https://dis.yaxpeax.net/&lt;arch&gt;/&lt;hex bytes&gt;`
additionally, the ?q query parameter can be used to remove the address and
byte framing, printing only disassembled instructions.

&lt;arch&gt; may be any of the supported architectures:
x86_64, x86_32, x86_16, x86:64, x86:32, x86:16,
ia64, armv7, armv8, avr, mips, msp430, pic17, pic18,
m16c, 6502, lc87, {sh{,2,3,4},j2}[[+-]{be,mmu,fpu,f64,j2}]*
</pre></body></html>";

fn usage() -> (StatusCode, String) {
    (StatusCode::OK, USAGE_STRING.to_string())
}

fn handle_req(req: &Request) -> (StatusCode, String) {
    let path = req.get_path();
    if path.len() == 0 {
        return usage();
    }

    let qs = req.get_query_str();
    let data = path;

    let quiet = match qs {
        None |
        Some("") |
        Some("q=0") => {
            false
        },
        Some("q") |
        Some("q=1") => {
            true
        },
        _ => {
            return usage();
        }
    };

    let parts: Vec<&str> = data.splitn(3, "/").collect();
    let (arch, buf) = match parts.as_slice() {
        &["", arch, data] => {
            match hex::decode(data) {
                Ok(buf) => (arch, buf),
                Err(e) => {
                    return (StatusCode::BAD_REQUEST, format!("provided bytes are not hex octets: {}", e));
                }
            }
        }
        _ => {
            return usage();
        }
    };

    match arch {
        "x86_64" |
        "x86:64" => crate::current_arch::decode_input_with_annotation::<yaxpeax_x86::long_mode::Arch>(&buf, quiet),
        "x86_32" |
        "x86:32" => crate::current_arch::decode_input_with_annotation::<yaxpeax_x86::protected_mode::Arch>(&buf, quiet),
        "x86_16" |
        "x86:16" => crate::current_arch::decode_input_with_annotation::<yaxpeax_x86::real_mode::Arch>(&buf, quiet),
        "ia64" => crate::current_arch::decode_input::<yaxpeax_ia64::IA64>(&buf, quiet),
        "avr" => crate::current_arch::decode_input::<yaxpeax_avr::AVR>(&buf, quiet),
        "armv7" => crate::current_arch::decode_input::<yaxpeax_arm::armv7::ARMv7>(&buf, quiet),
        "armv8" => crate::current_arch::decode_input::<yaxpeax_arm::armv8::a64::ARMv8>(&buf, quiet),
        "mips" => crate::current_arch::decode_input::<yaxpeax_mips::MIPS>(&buf, quiet),
        "msp430" => crate::current_arch::decode_input_with_annotation::<yaxpeax_msp430::MSP430>(&buf, quiet),
        "pic17" => crate::current_arch::decode_input::<yaxpeax_pic17::PIC17>(&buf, quiet),
        "pic18" => crate::current_arch::decode_input::<yaxpeax_pic18::PIC18>(&buf, quiet),
        "m16c" => crate::current_arch::decode_input::<yaxpeax_m16c::M16C>(&buf, quiet),
        "6502" => crate::current_arch::decode_input::<yaxpeax_6502::N6502>(&buf, quiet),
        "lc87" => crate::current_arch::decode_input::<yaxpeax_lc87::LC87>(&buf, quiet),
        other => {
            let seg_idx = other.find(&['+', '-'][..]).unwrap_or(other.len());
            let decode = |base| crate::current_arch::decode_input_with_decoder::<yaxpeax_superh::SuperH>(
                parse_superh(base, &other[seg_idx..]), &buf, quiet);
            match &other[0..seg_idx] {
                "sh" => decode(yaxpeax_superh::SuperHDecoder::SH1),
                "sh2" => decode(yaxpeax_superh::SuperHDecoder::SH2),
                "sh3" => decode(yaxpeax_superh::SuperHDecoder::SH3),
                "sh4" => decode(yaxpeax_superh::SuperHDecoder::SH4),
                "j2" => decode(yaxpeax_superh::SuperHDecoder::J2),
                other => (StatusCode::NOT_FOUND, format!("unsupported architecture: {}", other))
            }
        }
    }
}

fn parse_superh(mut based_on: yaxpeax_superh::SuperHDecoder, mut from: &str)
    -> yaxpeax_superh::SuperHDecoder
{
    while !from.is_empty() {
        let op = from.chars().next().unwrap();
        from = &from[1..];

        let next_feat_idx = from.find(&['+', '-'][..]).unwrap_or(from.len());
        let feat = &from[0..next_feat_idx];
        from = &from[next_feat_idx..];

        match (op, feat) {
            ('+', "be") => based_on.little_endian = false,
            ('-', "be") => based_on.little_endian = true,
            ('+', "f64") => based_on.fpscr_sz = true,
            ('-', "f64") => based_on.fpscr_sz = false,

            ('+', "mmu") => based_on.features.insert(yaxpeax_superh::SuperHFeatures::MMU),
            ('-', "mmu") => based_on.features.remove(yaxpeax_superh::SuperHFeatures::MMU),
            ('+', "fpu") => based_on.features.insert(yaxpeax_superh::SuperHFeatures::FPU),
            ('-', "fpu") => based_on.features.remove(yaxpeax_superh::SuperHFeatures::FPU),
            ('+', "j2") => based_on.features.insert(yaxpeax_superh::SuperHFeatures::J2),
            ('-', "j2") => based_on.features.remove(yaxpeax_superh::SuperHFeatures::J2),

            pair => panic!("Who is {:?} and why was it not caught at parse time?", pair),
        }
    }

    based_on
}

// yaxpeax-arch, implemented by all decoders here, is required at incompatible versions by
// different decoders. implement the actual decode-and-print behavior on both versions of
// yaxpeax-arch while older decoders are still being updated.
mod current_arch {
    use yaxpeax_arch_02::{AddressBase, Arch, Decoder, Instruction, LengthedInstruction, Reader, U8Reader};
    use yaxpeax_arch_02::annotation::{AnnotatingDecoder, FieldDescription, VecSink};
    use std::fmt;
    use std::fmt::Write;
    use num_traits::identities::Zero;
    use fastly::http::StatusCode;

    fn col2bit(col: usize) -> usize {
       // ia64
       // 127 - col
       // msp430
            /*
        let word = col >> 4;
        let bit = 15 - (col & 0xf);

        (word << 4) | bit
        */
        // x86
        let byte = col / 8;
        let bit = 7 - (col % 8);
        let bit = byte * 8 + bit;
        bit
    }
    fn bit2col(bit: usize) -> usize {
        let byte = bit / 8;
        let bit = 7 - (bit % 8);
        let bit = byte * 8 + bit;
        bit
    }

    #[derive(Debug)]
    struct BitRange {
        start: u32,
        end: u32,
        lhs: u32,
        rhs: u32,
    }

    impl BitRange {
        fn across(start: u32, end: u32) -> BitRange {
            let mut lhs = bit2col(start as usize) as u32;
            let mut rhs = bit2col(start as usize) as u32;
            for bit in start..=end {
                lhs = std::cmp::min(lhs, bit2col(bit as usize) as u32);
                rhs = std::cmp::max(rhs, bit2col(bit as usize) as u32);
            }
            BitRange { start, end, lhs, rhs }
        }
    }

    struct ItemDescription<A: Arch> where A::Decoder: AnnotatingDecoder<A> {
        ranges: Vec<BitRange>,
        description: <<A as Arch>::Decoder as AnnotatingDecoder<A>>::FieldDescription,
    }

    impl<A: Arch> fmt::Debug for ItemDescription<A> where A::Decoder: AnnotatingDecoder<A> {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "{{ ranges: {:?}, description: {} }}", &self.ranges, &self.description)
        }
    }

    // spans grouped together in some decoder-specified logical structure by
    // `id`. `id` is a hint that data should be considered related for display
    // purposes.
    struct FieldRecord<A: Arch> where A::Decoder: AnnotatingDecoder<A> {
        // spans grouped together by `FieldDescription` - one field may be
        // described by multiple distinct spans, so those spans are recorded
        // here. elements are ordered by the lowest bit of spans describing an
        // element.
        elements: Vec<ItemDescription<A>>,
        id: u32,
    }

    impl<A: Arch> fmt::Debug for FieldRecord<A> where A::Decoder: AnnotatingDecoder<A> {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "{{ elements: {:?}, id: {} }}", &self.elements, &self.id)
        }
    }

    fn show_field_descriptions<A: Arch>(res: &mut String, fields: &[FieldRecord<A>], data: &[u8]) where A::Decoder: AnnotatingDecoder<A> {
        let mut boundaries = [false; 256];
        let mut separators = [false; 256];
        let mut bits = [false; 256];
        let mut rhs = [false; 256];
        let mut lhs = [false; 256];
        let mut field_order: Vec<(usize, usize)> = Vec::new();
        let mut boundary_order: Vec<(usize, usize)> = Vec::new();

        for (fi, field) in fields.iter().enumerate() {
            for (ei, element) in field.elements.iter().enumerate() {
                if element.description.is_separator() {
                    for (_ri, range) in element.ranges.iter().enumerate() {
                        boundaries[range.start as usize + 1] = true;
                        boundary_order.push((fi, range.start as usize + 1));
                    }
                    continue;
                }
                field_order.push((fi, ei));
                for (_ri, range) in element.ranges.iter().enumerate() {
                    for i in range.start..=range.end {
                        bits[i as usize] = true;
                    }
                    separators[range.start as usize] = true;
                    lhs[range.lhs as usize] = true;
                    rhs[range.rhs as usize] = true;
                }
            }
        }
        boundary_order.sort_by(|l, r| r.1.cmp(&l.1));

        fn color_str(line_no: usize) -> &'static str {
            const LINES: [&'static str; 2] = [
                "background: #ddd;",
                "background: #eee;",
            ];
            LINES[line_no % 2]
        }

        let mut line = 0usize;

        // regardless of sections, the left-hand side of the terminal is a free boundary
        lhs[0] = false;

        res.push_str("<pre style=\"margin: 0\">");
        res.push_str("                                ");
        res.push_str("</pre>\n");

        let mut fudge_bits = [false; 160];

        for i in 0..160 {
            if (i >> 3) >= data.len() {
                continue;
            }

            let mut fudge = false;

            if lhs[i] {
                fudge = true;
            }

            if i > 0 && rhs[i - 1] {
                fudge = true;
            }

            if fudge {
                fudge_bits[i] = true;
            }
        }

        let mut fudge = 0;
        let mut col = [b' '; 160];

        for i in 0..160 {
            if (i >> 3) >= data.len() {
                continue;
            }

            let bit = col2bit(i);

            if fudge_bits[i] {
                fudge += 1;
            }

            if data[(bit >> 3) as usize] & (1 << (bit as u8 & 7)) != 0 {
                col[i + fudge] = b'1';
            } else {
                col[i + fudge] = b'0';
            }
        }
        res.push_str("<pre style=\"margin: 0\">");
        res.push_str(unsafe { std::str::from_utf8_unchecked(&col) });
        res.push_str("</pre>\n");

        for (fi, ei) in field_order.iter() {
            let mut col = [b' '; 160];

            for range in &fields[*fi as usize].elements[*ei as usize].ranges {
                let mut fudge = 0;

                for c in 0..128 {
                    let bit = col2bit(c as usize);

                    if boundaries[c] {
                        col[c + fudge] = b'|';
                    }
                    if fudge_bits[c as usize] {
                        fudge += 1;
                    }

                    if bit >= range.start as usize && bit <= range.end as usize {
                        let data_bit = data[(bit >> 3) as usize] & (1 << (bit as u8 & 7)) != 0;
                        col[c as usize + fudge] = if data_bit { b'1' } else { b'0' };
                    }
                }
            }

            res.push_str("<pre style=\"margin: 0;");
            res.push_str(color_str(line));
            res.push_str("\">");
            res.push_str(unsafe { std::str::from_utf8_unchecked(&col[..(data.len() * 8 + 30)]) });
            res.push_str(" ");
            res.push_str(&fields[*fi as usize].elements[*ei as usize].description.to_string());
            res.push_str("</pre>\n");
            line += 1;
        }

        let mut fudge = 0;
        let mut col = [b' '; 160];

        let mut line_end = 0;
        for i in 0..160 {
            if (i >> 3) > data.len() {
                continue;
            }

            if boundaries[i] {
                col[i + fudge] = b'|';
                line_end = i + fudge + 1;
            }
            if fudge_bits[i] {
                fudge += 1;
            }
        }
        res.push_str("<pre style=\"margin: 0;");
        res.push_str(color_str(line));
        res.push_str("\">");
        res.push_str(unsafe { std::str::from_utf8_unchecked(&col[..line_end]) });
        res.push_str("</pre>\n");
        line += 1;

        for (field_index, bit) in boundary_order {
            let mut fudge = 0;
            let mut col = [b' '; 160];

            res.push_str("<pre style=\"margin: 0;");
            res.push_str(color_str(line));
            res.push_str("\">");
            for i in 0..160 {
                if (i >> 3) > data.len() {
                    continue;
                }

                if i == bit {
                    res.push_str(unsafe { std::str::from_utf8_unchecked(&col[..i + fudge]) });
                    break;
                }

                if boundaries[i] {
                    col[i + fudge] = b'|';
                }
                if fudge_bits[i] {
                    fudge += 1;
                }
            }
            let _ = write!(res, "{}", fields[field_index].elements[0].description);
            res.push_str("</pre>\n");
            line += 1;
        }
    }

    pub(crate) fn decode_input<A: Arch>(buf: &[u8], quiet: bool) -> (StatusCode, String)
    where
        A::Instruction: fmt::Display, for<'data> U8Reader<'data>: Reader<A::Address, A::Word>,
    {
        decode_input_with_decoder::<A>(A::Decoder::default(), buf, quiet)
    }

    pub(crate) fn decode_input_with_annotation<A: Arch>(buf: &[u8], quiet: bool) -> (StatusCode, String)
    where
        A::Instruction: fmt::Display, for<'data> U8Reader<'data>: Reader<A::Address, A::Word>,
        A::Decoder: AnnotatingDecoder<A>,
    {
        decode_input_with_decoder_and_annotation::<A>(A::Decoder::default(), buf, quiet)
    }

    pub(crate) fn decode_input_with_decoder<A: Arch>(decoder: A::Decoder, buf: &[u8], quiet: bool) -> (StatusCode, String)
    where
        A::Instruction: fmt::Display, for<'data> U8Reader<'data>: Reader<A::Address, A::Word>,
    {
        let mut result = String::new();
        result.push_str("<html><body>");

        let start = A::Address::zero();
        let mut addr = start;
        loop {
            let mut reader = U8Reader::new(&buf[addr.to_linear()..]);
            match decoder.decode(&mut reader) {
                Ok(inst) => {
                    result.push_str("<pre style=\"margin: 0\">");
                    if !quiet {
                        let _ = write!(result, "{:#010x}: {:14}: ",
                            addr.to_linear(),
                            hex::encode(
                                &buf[addr.to_linear()..]
                                    [..A::Address::zero().wrapping_offset(inst.len()).to_linear()]
                            )
                        );
                    }
                    let _ = write!(result, "{}", inst);
                    result.push_str("</pre>\n");

                    if false {
                        result.push_str("<pre style=\"margin: 0\">");
                        let _ = write!(result, "  {:?}", inst);
                        result.push_str("</pre>\n");
                        if !inst.well_defined() {
                            result.push_str("<pre style=\"margin: 0\">");
                            let _ = write!(result, "  not well-defined");
                            result.push_str("</pre>\n");
                        }
                    }
                    addr += inst.len();
                }
                Err(e) => {
                    result.push_str("<pre style=\"margin: 0\">");
                    if !quiet {
                        let _ = write!(result, "{:#010x}: ", addr.to_linear());
                    }
                    let _ = write!(result, "{}", e);
                    result.push_str("</pre>\n");
                    addr += A::Instruction::min_size();
                }
            }
            if addr.to_linear() >= buf.len() {
                break;
            }
        }

        result.push_str("</body></html>");
        (StatusCode::OK, result)
    }

    pub(crate) fn decode_input_with_decoder_and_annotation<A: Arch>(decoder: A::Decoder, buf: &[u8], quiet: bool) -> (StatusCode, String)
    where
        A::Instruction: fmt::Display, for<'data> U8Reader<'data>: Reader<A::Address, A::Word>,
        A::Decoder: AnnotatingDecoder<A>,
    {
        let mut result = String::new();
        result.push_str("<html><body>");

        let start = A::Address::zero();
        let mut addr = start;
        loop {
            let mut sink: VecSink<<A::Decoder as AnnotatingDecoder<A>>::FieldDescription> = VecSink::new();
            let mut reader = U8Reader::new(&buf[addr.to_linear()..]);
            let mut inst = A::Instruction::default();
            match decoder.decode_with_annotation(&mut inst, &mut reader, &mut sink) {
                Ok(()) => {
                    result.push_str("<pre style=\"margin: 0\">");
                    if !quiet {
                        let _ = write!(result, "{:#010x}: {:14}: ",
                            addr.to_linear(),
                            hex::encode(
                                &buf[addr.to_linear()..]
                                    [..A::Address::zero().wrapping_offset(inst.len()).to_linear()]
                            )
                        );
                    }
                    let _ = write!(result, "{}", inst);
                    result.push_str("</pre>\n");

                    if false {
                        result.push_str("<pre style=\"margin: 0\">");
                        let _ = write!(result, "  {:?}", inst);
                        result.push_str("</pre>\n");
                        if !inst.well_defined() {
                            result.push_str("<pre style=\"margin: 0\">");
                            let _ = write!(result, "  not well-defined");
                            result.push_str("</pre>\n");
                        }
                    }
                    if !quiet {
                        let mut fields: Vec<FieldRecord<A>> = Vec::new();

                        use itertools::Itertools;
                        let mut vs = sink.records;
                        vs.sort_by_key(|rec| rec.2.id());
                        for (id, group) in &vs.iter().group_by(|x| x.2.id()) {
                            let mut field = FieldRecord {
                                elements: Vec::new(),
                                id: id,
                            };

                            for (desc, spans) in &group.group_by(|x| x.2.to_owned()) {
                                let mut item = ItemDescription {
                                    ranges: Vec::new(),
                                    description: desc,
                                };

                                for span in spans {
                                    item.ranges.push(BitRange::across(span.0, span.1));
                                }
                                field.elements.push(item);
                            }
                            fields.push(field);
                        }
                        show_field_descriptions(
                            &mut result,
                            &fields,
                            &buf[addr.to_linear()..]
                                [..A::Address::zero().wrapping_offset(inst.len()).to_linear()]
                        );
                    }
                    addr += inst.len();
                }
                Err(e) => {
                    result.push_str("<pre style=\"margin: 0\">");
                    write!(result, "{:#010x}: {}", addr.to_linear(), e);
                    result.push_str("</pre>\n");
                    addr += A::Instruction::min_size();
                }
            }
            if addr.to_linear() >= buf.len() {
                break;
            }
        }

        result.push_str("</body></html>");
        (StatusCode::OK, result)
    }
}

mod legacy_arch {
    use yaxpeax_arch_01::{AddressBase, Arch, Decoder, Instruction, LengthedInstruction};
    use std::fmt;
    use std::fmt::Write;
    use num_traits::identities::Zero;
    use fastly::http::StatusCode;

    #[allow(dead_code)]
    pub(crate) fn decode_input<A: Arch>(buf: &[u8], quiet: bool) -> (StatusCode, String)
    where
        A::Instruction: fmt::Display,
    {
        decode_input_with_decoder::<A>(A::Decoder::default(), buf, quiet)
    }

    pub(crate) fn decode_input_with_decoder<A: Arch>(decoder: A::Decoder, buf: &[u8], quiet: bool) -> (StatusCode, String)
    where
        A::Instruction: fmt::Display,
    {
        let mut result = String::new();
        result.push_str("<html><body>");

        let start = A::Address::zero();
        let mut addr = start;
        loop {
            match decoder.decode(buf[addr.to_linear()..].iter().cloned()) {
                Ok(inst) => {
                    result.push_str("<pre style=\"margin: 0\">");
                    if !quiet {
                        let _ = write!(result, "{:#010x}: {:14}: ",
                            addr.to_linear(),
                            hex::encode(
                                &buf[addr.to_linear()..]
                                    [..A::Address::zero().wrapping_offset(inst.len()).to_linear()]
                            )
                        );
                        result.push_str("</pre>\n");
                    }
                    let _ = write!(result, "{}", inst);
                    result.push_str("</pre>\n");

                    if false {
                        result.push_str("<pre style=\"margin: 0\">");
                        let _ = write!(result, "  {:?}", inst);
                        result.push_str("</pre>\n");
                        if !inst.well_defined() {
                            result.push_str("<pre style=\"margin: 0\">");
                            let _ = write!(result, "  not well-defined");
                            result.push_str("</pre>\n");
                        }
                    }
                    addr += inst.len();
                }
                Err(e) => {
                    result.push_str("<pre style=\"margin: 0\">");
                    if !quiet {
                        let _ = write!(result, "{:#010x}: ", addr.to_linear());
                    }
                    let _ = write!(result, "{}", e);
                    result.push_str("</pre>\n");
                    addr += A::Instruction::min_size();
                }
            }
            if addr.to_linear() >= buf.len() {
                break;
            }
        }

        result.push_str("</body></html>");
        (StatusCode::OK, result)
    }
}
