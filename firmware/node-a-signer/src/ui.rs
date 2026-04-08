use common::TransactionIntent;
use core::fmt::Write;
use critical_section::with as critical_section;
use embedded_graphics::{
    Drawable,
    draw_target::DrawTarget,
    geometry::Point,
    mono_font::{MonoTextStyle, ascii::{FONT_10X20, FONT_6X10, FONT_8X13_BOLD}},
    pixelcolor::{Rgb565, RgbColor},
    text::Text,
};
use heapless::String;

const DISPLAY_HEIGHT: i32 = 320;
const LINE_HEIGHT: i32 = 16;
const SHORT_PRESS_TEXT_Y: i32 = DISPLAY_HEIGHT - 56;
const LONG_PRESS_TEXT_Y: i32 = DISPLAY_HEIGHT - 36;
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

    fn draw_text_small(&mut self, text: &str, x: i32, y: i32) {
        let style = MonoTextStyle::new(&FONT_6X10, Rgb565::BLACK);
        let text = Text::new(text, Point::new(x, y), style);
        let _ = Drawable::draw(&text, &mut self.display);
    }

    fn draw_text_body(&mut self, text: &str, x: i32, y: i32) {
        let style = MonoTextStyle::new(&FONT_8X13_BOLD, Rgb565::BLACK);
        let text = Text::new(text, Point::new(x, y), style);
        let _ = Drawable::draw(&text, &mut self.display);
    }

    fn draw_text_large(&mut self, text: &str, x: i32, y: i32) {
        let style = MonoTextStyle::new(&FONT_10X20, Rgb565::BLACK);
        let text = Text::new(text, Point::new(x, y), style);
        let _ = Drawable::draw(&text, &mut self.display);
    }

    fn clear_screen(&mut self) {
        let _ = DrawTarget::clear(&mut self.display, Rgb565::WHITE);
    }

    fn render_screen<F>(&mut self, draw: F)
    where
        F: FnOnce(&mut Self),
    {
        critical_section(|_| {
            self.clear_screen();
            draw(self);
        });
    }

    fn draw_action_guide(&mut self) {
        let mut short_label: String<48> = String::new();
        let mut long_label: String<40> = String::new();

        let _ = write!(
            short_label,
            "Short {}-{}ms: OK",
            SHORT_PRESS_MIN_MS,
            LONG_PRESS_MIN_MS.saturating_sub(1)
        );
        let _ = write!(long_label, "Hold >= {}ms: Deny", LONG_PRESS_MIN_MS);

        self.draw_text_small(&short_label, 10, SHORT_PRESS_TEXT_Y);
        self.draw_text_small(&long_label, 10, LONG_PRESS_TEXT_Y);
    }

    pub fn display_address(&mut self, address_str: &str) {
        self.render_screen(|ui| {
            ui.draw_text_small("Wallet Address", 10, 18);

            let body = address_str.strip_prefix("0x").unwrap_or(address_str);
            let mut y = 42;
            for chunk in body.as_bytes().chunks(16) {
                if let Ok(line) = core::str::from_utf8(chunk) {
                    ui.draw_text_body(line, 10, y);
                    y += LINE_HEIGHT;
                }
            }

            ui.draw_text_small("Balance", 10, 120);
            ui.draw_text_large("0.0000", 10, 148);
            ui.draw_text_body("ETH", 10, 172);
            ui.draw_text_small("$0.00", 10, 190);
        });
    }

    pub fn display_sign_request(&mut self, hash: &[u8; 32]) {
        self.render_screen(|ui| {
            ui.draw_text_body("Sign Request", 10, 20);
            ui.draw_text_small("Review tx hash", 10, 40);

            let mut hex: String<64> = String::new();
            for b in hash {
                let _ = write!(hex, "{:02x}", b);
            }

            let mut y = 68;
            for chunk in hex.as_bytes().chunks(16) {
                if let Ok(line) = core::str::from_utf8(chunk) {
                    ui.draw_text_body(line, 10, y);
                    y += LINE_HEIGHT;
                }
            }

            ui.draw_action_guide();
        });
    }

    pub fn display_sign_request_intent(&mut self, intent: &TransactionIntent, hash: &[u8; 32]) {
        self.render_screen(|ui| {
            ui.draw_text_body("Sign Request", 10, 20);

            let mut line: String<32> = String::new();
            let _ = write!(line, "Chain ID: {}", intent.chain_id);
            ui.draw_text_body(&line, 10, 42);

            let mut addr: String<32> = String::new();
            let _ = write!(addr, "to: 0x");
            for b in &intent.target_address[..4] {
                let _ = write!(addr, "{:02x}", b);
            }
            let _ = write!(addr, "..");
            for b in &intent.target_address[16..] {
                let _ = write!(addr, "{:02x}", b);
            }
            ui.draw_text_body(&addr, 10, 58);

            let mut value: String<32> = String::new();
            let _ = write!(value, "Value wei: {}", intent.eth_value);
            ui.draw_text_body(&value, 10, 74);

            let risk = match intent.risk_level {
                0 => "SAFE",
                1 => "WARN",
                _ => "DANGER",
            };
            let mut risk_line: String<20> = String::new();
            let _ = write!(risk_line, "Risk: {}", risk);
            ui.draw_text_body(&risk_line, 10, 90);

            if !intent.summary.is_empty() {
                let mut summary: String<64> = String::new();
                let _ = write!(summary, "Summary: {}", intent.summary.as_str());
                ui.draw_text_body(&summary, 10, 110);
            }

            let mut h: String<24> = String::new();
            let _ = write!(h, "hash: ");
            for b in &hash[..4] {
                let _ = write!(h, "{:02x}", b);
            }
            ui.draw_text_body(&h, 10, 130);

            ui.draw_action_guide();
        });
    }

    pub fn display_pairing_request(&mut self, session_hint: Option<&str>) {
        self.render_screen(|ui| {
            ui.draw_text_body("Pair Request", 10, 20);
            ui.draw_text_small("Trust this gateway?", 10, 42);

            if let Some(hint) = session_hint {
                let mut buf: String<32> = String::new();
                let _ = write!(buf, "From: {}", hint);
                ui.draw_text_body(&buf, 10, 68);
            }

            ui.draw_action_guide();
        });
    }

    pub fn display_message(&mut self, title: &str, line1: &str, line2: &str) {
        self.render_screen(|ui| {
            ui.draw_text_body(title, 10, 20);
            ui.draw_text_body(line1, 10, 50);
            ui.draw_text_body(line2, 10, 50 + LINE_HEIGHT);
        });
    }
}
