use common::TransactionIntent;
use core::fmt::Write;
use embedded_graphics::{
    mono_font::{MonoTextStyle, ascii::FONT_6X10},
    pixelcolor::Rgb565,
    prelude::*,
    primitives::{PrimitiveStyle, Rectangle},
    text::Text,
};
use heapless::String;
use qrcodegen_no_heap::{QrCode, QrCodeEcc};

// 디스플레이 크기 (LILYGO T-Display S3 기준)
const DISPLAY_WIDTH: i32 = 170;
const DISPLAY_HEIGHT: i32 = 320;
const LINE_HEIGHT: i32 = 12;
const SHORT_PRESS_TEXT_Y: i32 = DISPLAY_HEIGHT - 50;
const LONG_PRESS_TEXT_Y: i32 = DISPLAY_HEIGHT - 35;
const SHORT_PRESS_MIN_MS: u16 = 80;
const LONG_PRESS_MIN_MS: u16 = 1200;

pub struct UiManager<D> {
    display: D,
}

impl<D> UiManager<D>
where
    D: DrawTarget<Color = Rgb565>,
    D::Error: core::fmt::Debug,
{
    pub fn new(display: D) -> Self {
        Self { display }
    }

    fn draw_line(&mut self, text: &str, x: i32, y: i32) {
        let text_style = MonoTextStyle::new(&FONT_6X10, Rgb565::WHITE);
        let _ = Text::new(text, Point::new(x, y), text_style).draw(&mut self.display);
    }

    fn clear_screen(&mut self) {
        let _ = self.display.clear(Rgb565::BLACK);
    }

    fn draw_action_guide(&mut self) {
        let mut short_label: String<48> = String::new();
        let mut long_label: String<40> = String::new();

        let _ = write!(
            short_label,
            "짧게 누름 ({}~{}ms): 승인",
            SHORT_PRESS_MIN_MS,
            LONG_PRESS_MIN_MS.saturating_sub(1)
        );
        let _ = write!(long_label, "길게 누름 (>= {}ms): 거절", LONG_PRESS_MIN_MS);

        self.draw_line(&short_label, 10, SHORT_PRESS_TEXT_Y);
        self.draw_line(&long_label, 10, LONG_PRESS_TEXT_Y);
    }

    pub fn display_address(&mut self, address_str: &str) {
        self.clear_screen();

        // qrcodegen-no-heap로 QR 코드 데이터를 생성한다.
        let mut temp_buffer = [0u8; 1024];
        let mut qr_buffer = [0u8; 1024];

        if let Ok(qr) = QrCode::encode_text(
            address_str,
            &mut temp_buffer,
            &mut qr_buffer,
            QrCodeEcc::Low,
            QrCode::MIN_VERSION,
            QrCode::MAX_VERSION,
            None,
            true,
        ) {
            // 170x320 화면 기준으로 중앙 정렬 후 그린다.
            let scale = 3;
            let x_offset = (DISPLAY_WIDTH - (qr.size() * scale)) / 2;
            let y_offset = 20;

            for y in 0..qr.size() {
                for x in 0..qr.size() {
                    if qr.get_module(x, y) {
                        // QR 모듈이 true면 흰색 사각형 하나씩 그림
                        let _ = Rectangle::new(
                            Point::new(x * scale + x_offset, y * scale + y_offset),
                            Size::new(scale as u32, scale as u32),
                        )
                        .into_styled(PrimitiveStyle::with_fill(Rgb565::WHITE))
                        .draw(&mut self.display);
                    }
                }
            }
        }

        // 주소 문자열은 화면 하단에 고정 표시
        self.draw_line(address_str, 5, 160);
    }

    pub fn display_sign_request(&mut self, hash: &[u8; 32]) {
        self.clear_screen();
        self.draw_line("서명 요청", 10, 20);
        self.draw_line("트랜잭션 상세: 해시 확인", 10, 40);

        // 해시 16바이트씩 끊어서 4줄로 표시
        let mut hex: String<64> = String::new();
        for b in hash {
            let _ = write!(hex, "{:02x}", b);
        }
        let mut y = 70;
        for chunk in hex.as_bytes().chunks(16) {
            if let Ok(line) = core::str::from_utf8(chunk) {
                self.draw_line(line, 10, y);
                y += LINE_HEIGHT;
            }
        }

        self.draw_action_guide();
    }

    pub fn display_sign_request_intent(&mut self, intent: &TransactionIntent, hash: &[u8; 32]) {
        self.clear_screen();
        self.draw_line("서명 요청", 10, 20);

        // 체인 ID
        let mut line: String<32> = String::new();
        let _ = write!(line, "체인 ID: {}", intent.chain_id);
        self.draw_line(&line, 10, 40);

        // 대상 주소(요약)
        let mut addr: String<32> = String::new();
        let _ = write!(addr, "to: 0x");
        for b in &intent.target_address[..4] {
            let _ = write!(addr, "{:02x}", b);
        }
        let _ = write!(addr, "..");
        for b in &intent.target_address[16..] {
            let _ = write!(addr, "{:02x}", b);
        }
        self.draw_line(&addr, 10, 55);

        // 금액(wei)
        let mut value: String<32> = String::new();
        let _ = write!(value, "금액(wei): {}", intent.eth_value);
        self.draw_line(&value, 10, 70);

        // 위험도
        let risk = match intent.risk_level {
            0 => "SAFE",
            1 => "WARN",
            _ => "DANGER",
        };
        let mut risk_line: String<20> = String::new();
        let _ = write!(risk_line, "위험도: {}", risk);
        self.draw_line(&risk_line, 10, 85);

        // 요약
        if !intent.summary.is_empty() {
            let mut summary: String<64> = String::new();
            let _ = write!(summary, "요약: {}", intent.summary.as_str());
            self.draw_line(&summary, 10, 105);
        }

        // 요청 해시(앞 4바이트 미리보기)
        let mut h: String<24> = String::new();
        let _ = write!(h, "hash: ");
        for b in &hash[..4] {
            let _ = write!(h, "{:02x}", b);
        }
        self.draw_line(&h, 10, 125);

        self.draw_action_guide();
    }

    pub fn display_pairing_request(&mut self, session_hint: Option<&str>) {
        self.clear_screen();
        self.draw_line("페어링 요청", 10, 20);
        self.draw_line("이 PC와 연결할까요?", 10, 40);

        if let Some(hint) = session_hint {
            let mut buf: String<32> = String::new();
            let _ = write!(buf, "장치: {}", hint);
            self.draw_line(&buf, 10, 70);
        }

        self.draw_action_guide();
    }

    pub fn display_message(&mut self, title: &str, line1: &str, line2: &str) {
        self.clear_screen();
        self.draw_line(title, 10, 20);
        self.draw_line(line1, 10, 50);
        self.draw_line(line2, 10, 50 + LINE_HEIGHT);
    }
}
