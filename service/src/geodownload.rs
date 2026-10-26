//! Optional public GeoIP database download (DB-IP City Lite). Never transmits observed endpoints.
use std::io::{Read, Write};
use std::path::Path;
use std::time::{Duration, Instant};

const ATTRIBUTION: &str = "IP Geolocation by DB-IP — https://db-ip.com/ — CC BY 4.0 https://creativecommons.org/licenses/by/4.0/";

fn month() -> String {
    // Civil date from the Unix epoch (UTC), enough for the monthly file name.
    let days = (crate::intel::now() / 86400.0) as i64 + 719_468;
    let era = days.div_euclid(146_097);
    let doe = days - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!("{y:04}-{m:02}")
}

pub fn download_city(directory: &Path) -> Result<String, String> {
    let month = month();
    let url = format!("https://download.db-ip.com/free/dbip-city-lite-{month}.mmdb.gz");
    let token = format!("{:x}", (crate::intel::now() * 1000.0) as u64);
    let decoded = directory.join(format!("geoip-{token}.mmdb.tmp"));
    let target = directory.join(format!("dbip-city-lite-{month}-{token}.mmdb"));
    let started = Instant::now();
    let result = (|| {
        let agent: ureq::Agent = ureq::Agent::config_builder().max_redirects(0).timeout_global(Some(Duration::from_secs(110))).build().into();
        let mut response = agent.get(&url).header("User-Agent", crate::intel::USER_AGENT).call().map_err(|e| e.to_string())?;
        let body = response.body_mut().with_config().limit(150_000_000).reader();
        let mut gz = flate2::read::GzDecoder::new(body);
        let mut out = std::fs::File::create(&decoded).map_err(|e| e.to_string())?;
        let (mut buf, mut total) = (vec![0u8; 1 << 16], 0u64);
        loop {
            let n = gz.read(&mut buf).map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            total += n as u64;
            if total > 400_000_000 || started.elapsed() > Duration::from_secs(110) {
                return Err("Geolocation database exceeded its size or time limit".to_string());
            }
            out.write_all(&buf[..n]).map_err(|e| e.to_string())?;
        }
        drop(out);
        crate::intel::validate_city_db(&decoded.to_string_lossy()).map_err(|_| "The downloaded database is not a City database".to_string())?;
        std::fs::rename(&decoded, &target).map_err(|e| e.to_string())?;
        let _ = std::fs::write(directory.join("DB-IP-LICENSE.txt"), format!("{ATTRIBUTION}\n"));
        Ok(target.to_string_lossy().into_owned())
    })();
    let _ = std::fs::remove_file(&decoded);
    result
}

#[cfg(test)]
mod tests {
    #[test]
    fn month_format() {
        let m = super::month();
        assert!(m.len() == 7 && m.as_bytes()[4] == b'-' && m.starts_with("20"));
    }
}
