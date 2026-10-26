//! Real application icons (Windows) as PNG, cached per executable path.
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

static CACHE: Mutex<Option<HashMap<String, Option<Vec<u8>>>>> = Mutex::new(None);
const BRAND: &[u8] = include_bytes!("../../assets/beaver.png");

fn base64(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for c in bytes.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            out.push(if i <= c.len() { T[(n >> (18 - 6 * i) & 63) as usize] as char } else { '=' });
        }
    }
    out
}

fn temp_dir() -> PathBuf {
    let dir = std::env::temp_dir().join("beaver-icons");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

#[cfg(windows)]
fn extract(path: &str) -> Option<Vec<u8>> {
    use windows_sys::Win32::Graphics::Gdi::*;
    use windows_sys::Win32::UI::Shell::{SHGetFileInfoW, SHFILEINFOW, SHGFI_ICON, SHGFI_LARGEICON};
    use windows_sys::Win32::UI::WindowsAndMessaging::{DestroyIcon, GetIconInfo, ICONINFO};
    unsafe {
        let wide: Vec<u16> = path.encode_utf16().chain([0]).collect();
        let mut info: SHFILEINFOW = std::mem::zeroed();
        if SHGetFileInfoW(wide.as_ptr(), 0, &mut info, std::mem::size_of::<SHFILEINFOW>() as u32, SHGFI_ICON | SHGFI_LARGEICON) == 0 || info.hIcon.is_null() {
            return None;
        }
        let mut ii: ICONINFO = std::mem::zeroed();
        let ok = GetIconInfo(info.hIcon, &mut ii) != 0;
        let result = (|| {
            if !ok || ii.hbmColor.is_null() {
                return None;
            }
            let mut bm: BITMAP = std::mem::zeroed();
            GetObjectW(ii.hbmColor as _, std::mem::size_of::<BITMAP>() as i32, &mut bm as *mut _ as _);
            let (w, h) = (bm.bmWidth, bm.bmHeight);
            if w <= 0 || h <= 0 || w > 256 || h > 256 {
                return None;
            }
            let mut bi: BITMAPINFO = std::mem::zeroed();
            bi.bmiHeader.biSize = std::mem::size_of::<BITMAPINFOHEADER>() as u32;
            bi.bmiHeader.biWidth = w;
            bi.bmiHeader.biHeight = -h; // top-down rows
            bi.bmiHeader.biPlanes = 1;
            bi.bmiHeader.biBitCount = 32;
            let mut px = vec![0u8; (w * h * 4) as usize];
            let dc = GetDC(std::ptr::null_mut());
            let rows = GetDIBits(dc, ii.hbmColor, 0, h as u32, px.as_mut_ptr() as _, &mut bi, DIB_RGB_COLORS);
            ReleaseDC(std::ptr::null_mut(), dc);
            if rows == 0 {
                return None;
            }
            let has_alpha = px.chunks(4).any(|p| p[3] != 0);
            for p in px.chunks_mut(4) {
                p.swap(0, 2); // BGRA -> RGBA
                if !has_alpha {
                    p[3] = 255; // legacy icons without an alpha channel
                }
            }
            let mut out = vec![];
            {
                let mut enc = png::Encoder::new(&mut out, w as u32, h as u32);
                enc.set_color(png::ColorType::Rgba);
                enc.set_depth(png::BitDepth::Eight);
                let mut writer = enc.write_header().ok()?;
                writer.write_image_data(&px).ok()?;
            }
            Some(out)
        })();
        if !ii.hbmColor.is_null() {
            DeleteObject(ii.hbmColor as _);
        }
        if !ii.hbmMask.is_null() {
            DeleteObject(ii.hbmMask as _);
        }
        DestroyIcon(info.hIcon);
        result
    }
}

#[cfg(not(windows))]
fn extract(_path: &str) -> Option<Vec<u8>> {
    None // Linux: the UI keeps its letter avatar
}

fn png(path: &str) -> Option<Vec<u8>> {
    let mut cache = CACHE.lock().unwrap();
    let map = cache.get_or_insert_with(HashMap::new);
    if map.len() > 500 {
        map.clear();
    }
    map.entry(path.to_string()).or_insert_with(|| extract(path)).clone()
}

pub fn data_url(path: &str) -> Option<String> {
    png(path).map(|p| format!("data:image/png;base64,{}", base64(&p)))
}

/// A PNG file for notification icons (toasts take a file path).
pub fn png_file(path: &str) -> Option<PathBuf> {
    use std::hash::{Hash, Hasher};
    let bytes = png(path)?;
    let mut h = std::collections::hash_map::DefaultHasher::new();
    path.hash(&mut h);
    let file = temp_dir().join(format!("{:016x}.png", h.finish()));
    if !file.exists() {
        std::fs::write(&file, bytes).ok()?;
    }
    Some(file)
}

pub fn brand_png() -> Option<PathBuf> {
    let file = temp_dir().join("beaver.png");
    if !file.exists() {
        std::fs::write(&file, BRAND).ok()?;
    }
    Some(file)
}
