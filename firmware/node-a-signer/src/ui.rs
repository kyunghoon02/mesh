use embedded_graphics::{
    mono_font::{ascii::FONT_6X10, MonoTextStyle},
    pixelcolor::Rgb565,
    prelude::*,
    primitives::{PrimitiveStyle, Rectangle},
    text::Text,
};
use qrcodegen_no_heap::{QrCode, QrCodeEcc};

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

    pub fn display_address(&mut self, address_str: &str) {
        let _ = self.display.clear(Rgb565::BLACK);

        // qrcodegen-no-heap 버퍼 (힙 할당 없음)
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
            // 170px 가로 기준 중앙 정렬 (회전 시 값 조정)
            let scale = 3;
            let x_offset = (170 - (qr.size() * scale)) / 2;
            let y_offset = 20;

            for y in 0..qr.size() {
                for x in 0..qr.size() {
                    if qr.get_module(x, y) {
                        // QR 모듈을 픽셀 블록으로 렌더링
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

        // 주소 텍스트는 QR 아래에 표시 (회전/해상도에 맞춰 조정)
        let text_style = MonoTextStyle::new(&FONT_6X10, Rgb565::WHITE);
        let _ = Text::new(address_str, Point::new(5, 160), text_style)
            .draw(&mut self.display);
    }
}
