"""
Estrazione metadati per Digital Forensics e OSINT.

Combina più fonti (firma file, hash, Pillow, exifread, XMP, profilo colore)
per ricostruire il massimo di contesto tecnico possibile dall'immagine.
"""

from __future__ import annotations

import hashlib
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from io import BytesIO
from pathlib import Path
from typing import Any, BinaryIO, Union

import exifread
import folium
import imagehash
from PIL import ExifTags, Image, UnidentifiedImageError
from PIL.ExifTags import IFD

# ID IFD standard EXIF (compatibili anche se l'enum Pillow non espone tutti i nomi)
_IFD_EXIF = int(getattr(IFD, "Exif", 0x8769))
_IFD_GPS = int(getattr(IFD, "GPS", getattr(IFD, "GPSInfo", 0x8825)))
_IFD_IFD1 = int(getattr(IFD, "IFD1", 1))
_IFD_INTEROP = getattr(IFD, "Interop", None)
_IFD_INTEROP_INT = int(_IFD_INTEROP) if _IFD_INTEROP is not None else None


def _ifd_short_name(ifd_key: Any) -> str:
    """Nome breve per intestazioni tabella (enum o intero)."""
    if isinstance(ifd_key, int):
        return {0x8769: "EXIF", 0x8825: "GPS", 1: "IFD1", 0xA005: "Interop"}.get(ifd_key, f"IFD_0x{ifd_key:x}")
    name = getattr(ifd_key, "name", None)
    return str(name) if name else str(ifd_key)


# Input: percorso, bytes o file-like binario (es. Streamlit UploadedFile)
ImageInput = Union[str, Path, bytes, BinaryIO]


@dataclass
class ExifAnalysisResult:
    """
    Risultato completo dell'analisi.

    sections: dizionario "nome sezione" -> tabella chiave/valore (tutto stringhe, adatto a UI).
    messages: avvisi informativi (es. assenza GPS, metadati parziali).
    error: messaggio unico solo in caso di fallimento grave (file illeggibile).
    """

    sections: dict[str, dict[str, str]] = field(default_factory=dict)
    latitude: float | None = None
    longitude: float | None = None
    altitude_m: float | None = None
    folium_map: folium.Map | None = None
    messages: list[str] = field(default_factory=list)
    error: str | None = None

    # Compatibilità con codice che legge ancora .metadata / .message
    @property
    def metadata(self) -> dict[str, str]:
        """Unione ordinata di tutte le sezioni (chiave prefissata con la sezione)."""
        merged: dict[str, str] = {}
        for sec_name, table in sorted(self.sections.items(), key=lambda x: x[0].lower()):
            for k, v in table.items():
                merged[f"{sec_name} — {k}"] = v
        return merged

    @property
    def message(self) -> str | None:
        """Primo messaggio utile: errore, oppure primo avviso, opzione None."""
        if self.error:
            return self.error
        if self.messages:
            return self.messages[0]
        return None


# Traduzioni etichette exifread frequenti (OSINT / fotografia)
_EXIFREAD_LABEL_IT: dict[str, str] = {
    "Image Make": "Produttore (Make)",
    "Image Model": "Modello fotocamera",
    "Image DateTime": "Data/ora (IFD0)",
    "EXIF DateTimeOriginal": "Data/ora scatto originale",
    "EXIF DateTimeDigitized": "Data/ora digitalizzazione",
    "EXIF OffsetTime": "Fuso orario (offset)",
    "EXIF OffsetTimeOriginal": "Fuso orario scatto originale",
    "EXIF OffsetTimeDigitized": "Fuso orario digitalizzazione",
    "EXIF SubSecTimeOriginal": "Frazioni di secondo (originale)",
    "EXIF LensModel": "Modello obiettivo",
    "EXIF LensMake": "Produttore obiettivo",
    "EXIF LensSpecification": "Specifiche obiettivo",
    "EXIF FNumber": "Apertura diaframma (F-number)",
    "EXIF ExposureTime": "Tempo di esposizione",
    "EXIF ShutterSpeedValue": "Tempo (valore APEX)",
    "EXIF ApertureValue": "Apertura (valore APEX)",
    "EXIF BrightnessValue": "Luminosità (APEX)",
    "EXIF ExposureBiasValue": "Compensazione esposizione",
    "EXIF MaxApertureValue": "Apertura massima",
    "EXIF FocalLength": "Lunghezza focale",
    "EXIF FocalLengthIn35mmFilm": "Focale equivalente 35mm",
    "EXIF ISOSpeedRatings": "ISO",
    "EXIF PhotographicSensitivity": "Sensibilità fotografica",
    "EXIF Flash": "Flash",
    "EXIF MeteringMode": "Modalità misurazione",
    "EXIF WhiteBalance": "Bilanciamento del bianco",
    "EXIF SceneCaptureType": "Tipo scena",
    "EXIF ExposureProgram": "Programma esposizione",
    "EXIF ExposureMode": "Modalità esposizione",
    "EXIF SensingMethod": "Metodo sensore",
    "EXIF CustomRendered": "Elaborazione personalizzata",
    "EXIF DigitalZoomRatio": "Rapporto zoom digitale",
    "EXIF SceneType": "Tipo scena (diretto)",
    "EXIF BodySerialNumber": "Numero di serie corpo",
    "EXIF LensSerialNumber": "Numero di serie obiettivo",
    "EXIF UserComment": "Commento utente",
    "EXIF Software": "Software (EXIF)",
    "Image Software": "Software (IFD0)",
    "Image Artist": "Artista",
    "Image Copyright": "Copyright",
    "Image HostComputer": "Computer di origine",
    "Image Orientation": "Orientamento",
    "Image XResolution": "Risoluzione X",
    "Image YResolution": "Risoluzione Y",
    "Image ResolutionUnit": "Unità risoluzione",
    "GPS GPSLatitude": "Latitudine GPS (raw)",
    "GPS GPSLongitude": "Longitudine GPS (raw)",
    "GPS GPSAltitude": "Altitudine GPS",
    "GPS GPSAltitudeRef": "Riferimento altitudine",
    "GPS GPSImgDirection": "Direzione inquadratura",
    "GPS GPSSpeed": "Velocità GPS",
    "GPS GPSDate": "Data GPS",
    "GPS GPSHPositioningError": "Errore posizionamento orizzontale",
    "GPS GPSProcessingMethod": "Metodo elaborazione GPS",
    "Thumbnail Compression": "Thumbnail — compressione",
    "Thumbnail JPEGInterchangeFormat": "Thumbnail — offset JPEG",
    "Thumbnail JPEGInterchangeFormatLength": "Thumbnail — lunghezza JPEG",
}


def _open_stream(source: ImageInput) -> BinaryIO:
    if isinstance(source, (str, Path)):
        return open(Path(source), "rb")
    if isinstance(source, bytes):
        return BytesIO(source)
    try:
        source.seek(0)
    except (AttributeError, OSError):
        pass
    return source


def _ratio_to_float(value: Any) -> float:
    if value is None:
        return 0.0
    if hasattr(value, "num") and hasattr(value, "den"):
        den = float(value.den) if value.den else 1.0
        return float(value.num) / den
    if isinstance(value, (tuple, list)) and len(value) >= 2:
        den = float(value[1]) if value[1] else 1.0
        return float(value[0]) / den
    return float(value)


def _dms_to_decimal(dms: Any, ref: str | None) -> float | None:
    if not dms or ref is None:
        return None
    try:
        parts = list(dms)
        if len(parts) < 3:
            return None
        degrees = _ratio_to_float(parts[0])
        minutes = _ratio_to_float(parts[1])
        seconds = _ratio_to_float(parts[2])
        dd = degrees + (minutes / 60.0) + (seconds / 3600.0)
        ref_upper = str(ref).upper().strip()
        if ref_upper in ("S", "W"):
            dd = -dd
        return dd
    except (TypeError, ValueError, ZeroDivisionError, IndexError):
        return None


def _exifread_tags_to_dict(tags: dict[str, Any]) -> dict[str, str]:
    """Converte i tag exifread in stringhe sicure (niente dump enormi di thumbnail)."""
    out: dict[str, str] = {}
    for key, tag in tags.items():
        label = _EXIFREAD_LABEL_IT.get(key, key)
        if key == "JPEGThumbnail" or key.startswith("Thumbnail ") and "Interchange" not in key:
            try:
                raw_len = len(tag.values) if hasattr(tag, "values") and tag.values is not None else 0
            except TypeError:
                raw_len = 0
            if raw_len == 0 and hasattr(tag, "printable"):
                pl = str(tag.printable)
                raw_len = len(pl) if pl.startswith("0x") or len(pl) > 200 else 0
            out[label or key] = f"[Dati binari thumbnail, ~{raw_len} byte — omessi dalla tabella]"
            continue
        try:
            printable = tag.printable
        except Exception:  # noqa: BLE001
            printable = str(tag)
        text = str(printable)
        if len(text) > 4000:
            text = text[:4000] + "… [troncato per lunghezza]"
        out[label] = text
    return dict(sorted(out.items(), key=lambda x: x[0].lower()))


def _extract_gps_from_exifread(tags: dict[str, Any]) -> tuple[float | None, float | None, float | None]:
    lat_tag = tags.get("GPS GPSLatitude")
    lat_ref = tags.get("GPS GPSLatitudeRef")
    lon_tag = tags.get("GPS GPSLongitude")
    lon_ref = tags.get("GPS GPSLongitudeRef")
    alt_tag = tags.get("GPS GPSAltitude")
    alt_ref = tags.get("GPS GPSAltitudeRef")

    lat = lon = None
    if lat_tag and lon_tag and lat_ref and lon_ref:
        lat_values = getattr(lat_tag, "values", None) or lat_tag
        lon_values = getattr(lon_tag, "values", None) or lon_tag
        lat = _dms_to_decimal(lat_values, lat_ref.printable if lat_ref else None)
        lon = _dms_to_decimal(lon_values, lon_ref.printable if lon_ref else None)

    alt_m: float | None = None
    if alt_tag is not None:
        try:
            v = alt_tag.values if hasattr(alt_tag, "values") else alt_tag
            if isinstance(v, (list, tuple)) and v:
                alt_m = _ratio_to_float(v[0])
            else:
                alt_m = float(alt_tag.printable)
            if alt_ref is not None and str(alt_ref.printable).strip() == "1":
                alt_m = -alt_m if alt_m is not None else None
        except (TypeError, ValueError, AttributeError):
            alt_m = None
    return lat, lon, alt_m


def _rational_tuple_to_float(value: Any) -> float | None:
    """Converte valori EXIF Pillow (Rational, IFDRational, tuple, int) in float."""
    if value is None:
        return None
    if hasattr(value, "numerator") and hasattr(value, "denominator"):
        den = float(value.denominator) if value.denominator else 1.0
        return float(value.numerator) / den
    if hasattr(value, "num") and hasattr(value, "den"):
        den = float(value.den) if value.den else 1.0
        return float(value.num) / den
    if isinstance(value, tuple) and len(value) == 2:
        try:
            n, d = value
            if d == 0:
                return float(n)
            return float(n) / float(d)
        except (TypeError, ValueError):
            return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _decimal_from_dms_rationals(value: Any) -> float | None:
    """
    Converte il valore EXIF GPS standard (tupla di 3 Rational: gradi, primi, secondi) in gradi decimali.
    """
    if value is None:
        return None
    if not isinstance(value, (list, tuple)) or len(value) < 3:
        return None
    d = _rational_tuple_to_float(value[0])
    m = _rational_tuple_to_float(value[1])
    s = _rational_tuple_to_float(value[2])
    if d is None or m is None or s is None:
        return None
    return d + (m / 60.0) + (s / 3600.0)


def _gps_from_pillow_exif(exif: Any) -> tuple[float | None, float | None, float | None]:
    """GPS da Pillow IFD (backup se exifread non decodifica o manca il blocco)."""
    try:
        gps = exif.get_ifd(_IFD_GPS)
    except Exception:  # noqa: BLE001
        return None, None, None
    if not gps:
        return None, None, None

    # IFD GPS: 1=LatRef, 2=Lat (DMS), 3=LonRef, 4=Lon (DMS), 5=AltRef, 6=Alt
    lat = _decimal_from_dms_rationals(gps.get(2))
    lon = _decimal_from_dms_rationals(gps.get(4))
    if lat is None or lon is None:
        return None, None, None

    ref_lat = gps.get(1)
    ref_lon = gps.get(3)
    if isinstance(ref_lat, bytes):
        ref_lat = ref_lat.decode("ascii", errors="ignore")
    if isinstance(ref_lon, bytes):
        ref_lon = ref_lon.decode("ascii", errors="ignore")
    if str(ref_lat).upper().startswith("S"):
        lat = -lat
    if str(ref_lon).upper().startswith("W"):
        lon = -lon

    alt_m: float | None = None
    if 6 in gps:
        alt_m = _rational_tuple_to_float(gps.get(6))
        ref_alt = gps.get(5)
        if ref_alt == 1 and alt_m is not None:
            alt_m = -alt_m
    return lat, lon, alt_m


def _pillow_exif_table(exif: Any) -> dict[str, str]:
    """Tabella leggibile da tutti i tag EXIF Pillow (IFD principali)."""
    if exif is None:
        return {}
    out: dict[str, str] = {}

    ifd_enums: list[int] = [_IFD_EXIF, _IFD_GPS, _IFD_IFD1]
    if _IFD_INTEROP_INT is not None:
        ifd_enums.append(_IFD_INTEROP_INT)

    for ifd_key in ifd_enums:
        try:
            ifd_data = exif.get_ifd(ifd_key)
        except Exception:  # noqa: BLE001
            continue
        if not ifd_data:
            continue
        prefix = _ifd_short_name(ifd_key)
        tag_map = ExifTags.GPSTAGS if ifd_key == _IFD_GPS else ExifTags.TAGS
        for k, v in ifd_data.items():
            name = tag_map.get(k, str(k))
            key = f"{prefix}: {name}"
            if isinstance(v, bytes):
                try:
                    decoded = v.decode("utf-8", errors="replace")
                except Exception:  # noqa: BLE001
                    decoded = repr(v[:80])
                if len(decoded) > 2000:
                    decoded = decoded[:2000] + "…"
                out[key] = decoded
            elif isinstance(v, tuple) and len(v) == 2:
                out[key] = f"{v[0]}/{v[1]}"
            else:
                sv = str(v)
                out[key] = sv[:4000] + ("…" if len(sv) > 4000 else "")

    # Tag radice (IFD0)
    for k, v in exif.items():
        tag = ExifTags.TAGS.get(k, str(k))
        if k in {34665, 34853}:  # ExifIFD, GPSInfo — già coperti sopra
            continue
        key = f"IFD0: {tag}"
        if isinstance(v, bytes):
            out[key] = v.decode("utf-8", errors="replace")[:2000]
        else:
            sv = str(v)
            out[key] = sv[:4000] + ("…" if len(sv) > 4000 else "")

    return dict(sorted(out.items(), key=lambda x: x[0].lower()))


def _pillow_image_info(img: Image.Image) -> dict[str, str]:
    """Campi Image.info (PNG tEXt, compressione, ICC, ecc.) senza blob enormi."""
    info_out: dict[str, str] = {}
    for name, val in (img.info or {}).items():
        if name == "icc_profile" and isinstance(val, bytes):
            info_out["ICC profile"] = f"Presente, {len(val)} byte (profilo colore incorporato)"
            continue
        if isinstance(val, bytes):
            if len(val) > 512:
                info_out[name] = f"[Binario {len(val)} byte — non mostrato integralmente]"
            else:
                info_out[name] = repr(val)
            continue
        s = str(val)
        if len(s) > 3000:
            s = s[:3000] + "…"
        info_out[str(name)] = s
    return dict(sorted(info_out.items(), key=lambda x: x[0].lower()))


def _file_signature(raw: bytes) -> str:
    if len(raw) < 12:
        return "File troppo corto"
    if raw[:2] == b"\xff\xd8":
        return "JPEG (FF D8)"
    if raw[:8] == b"\x89PNG\r\n\x1a\n":
        return "PNG"
    if raw[:6] in (b"GIF87a", b"GIF89a"):
        return "GIF"
    if raw[:4] == b"RIFF" and raw[8:12] == b"WEBP":
        return "WEBP (RIFF)"
    if raw[:4] == b"II*\x00" or raw[:4] == b"MM\x00*":
        return "TIFF"
    return f"Sconosciuta (primi byte hex: {raw[:8].hex()})"


def _parse_xmp_simple(xmp_xml: str) -> dict[str, str]:
    """
    Estrae coppie chiave/valore utili da XMP (Adobe, DC, Photoshop).
    XML da immagine considerato di dimensione limitata; parsing best-effort.
    """
    out: dict[str, str] = {}
    if not xmp_xml or len(xmp_xml) > 800_000:
        xmp_xml = xmp_xml[:800_000]
    try:
        root = ET.fromstring(xmp_xml)
    except ET.ParseError:
        # fallback: regex su attributi comuni
        for pattern, label in (
            (r'xmp:CreatorTool="([^"]*)"', "XMP CreatorTool"),
            (r'photoshop:DateCreated="([^"]*)"', "Photoshop DateCreated"),
            (r'photoshop:Credit="([^"]*)"', "Photoshop Credit"),
            (r'photoshop:Source="([^"]*)"', "Photoshop Source"),
            (r'photoshop:City="([^"]*)"', "Photoshop City"),
            (r'photoshop:Country="([^"]*)"', "Photoshop Country"),
            (r'dc:title[^>]*>.*?<rdf:li[^>]*>([^<]+)', "DC Title"),
            (r'dc:creator[^>]*>.*?<rdf:li[^>]*>([^<]+)', "DC Creator"),
        ):
            m = re.search(pattern, xmp_xml, re.DOTALL | re.IGNORECASE)
            if m:
                out[label] = m.group(1).strip()[:2000]
        return out

    def local(tag: str) -> str:
        if "}" in tag:
            return tag.split("}", 1)[1]
        return tag

    for el in root.iter():
        tag = local(el.tag)
        text = (el.text or "").strip()
        if not text and el.attrib:
            for ak, av in el.attrib.items():
                lk = local(ak)
                if av and lk not in {"about", "rdf:parseType"}:
                    key = f"{tag} @{lk}"
                    if len(av) < 500:
                        out[key] = av
        elif text and len(text) < 4000:
            out[tag] = text

    # Riduci rumore: tieni chiavi più informative
    noise = {"RDF", "Description", "Seq", "Bag", "Alt", "li", "type"}
    filtered = {k: v for k, v in out.items() if k.split("@")[0] not in noise or "photoshop" in k.lower() or "xmp" in k.lower()}
    return dict(sorted((filtered or out).items(), key=lambda x: x[0].lower())[:80])


def _xmp_from_image(img: Image.Image) -> dict[str, str]:
    getter = getattr(img, "getxmp", None)
    if not callable(getter):
        return {}
    try:
        xml_str = getter()
    except Exception:  # noqa: BLE001
        return {}
    if not xml_str or not isinstance(xml_str, str):
        return {}
    return _parse_xmp_simple(xml_str)


def _visual_hashes(img: Image.Image) -> dict[str, str]:
    """Hash percettivi utili per correlare la stessa immagine o varianti compresse."""
    try:
        rgb = img.convert("RGB")
        return {
            "pHash (perceptual)": str(imagehash.phash(rgb)),
            "aHash (average)": str(imagehash.average_hash(rgb)),
            "dHash (difference)": str(imagehash.dhash(rgb)),
            "wHash (wavelet)": str(imagehash.whash(rgb)),
        }
    except Exception as e:  # noqa: BLE001
        return {"Errore hash visivo": str(e)}


def _build_folium_map(
    lat: float,
    lon: float,
    altitude_m: float | None,
    extra_lines: list[str],
) -> folium.Map:
    m = folium.Map(location=[lat, lon], zoom_start=14, control_scale=True)
    popup_html = f"<b>Posizione EXIF/GPS</b><br>Lat: {lat:.6f}<br>Lon: {lon:.6f}"
    if altitude_m is not None:
        popup_html += f"<br>Altitudine stimata: {altitude_m:.1f} m"
    for line in extra_lines[:8]:
        popup_html += f"<br>{line}"
    folium.Marker([lat, lon], popup=folium.Popup(popup_html, max_width=320), tooltip="Punto GPS").add_to(m)
    return m


def analyze_exif(source: ImageInput) -> ExifAnalysisResult:
    """
    Analisi completa: tecnica + EXIF (exifread + Pillow) + XMP + GPS/mappa.
    """
    close_after = False
    stream: BinaryIO | None = None
    sections: dict[str, dict[str, str]] = {}
    messages: list[str] = []

    try:
        stream = _open_stream(source)
        if isinstance(source, (str, Path)):
            close_after = True

        raw = stream.read()
        if not raw:
            return ExifAnalysisResult(error="Il file è vuoto o non è stato letto correttamente.")

        pillow_exif: Any = None
        try:
            with Image.open(BytesIO(raw)) as img:
                img.load()
                fmt = img.format or "?"
                mode = img.mode
                w, h = img.size
                pillow_exif = img.getexif() if hasattr(img, "getexif") else None

                tech: dict[str, str] = {
                    "Firma file (magic)": _file_signature(raw),
                    "Formato Pillow": str(fmt),
                    "Modalità colore": str(mode),
                    "Dimensioni pixel": f"{w} × {h}",
                    "Dimensione file": f"{len(raw):,} byte ({len(raw) / 1024:.2f} KiB)",
                    "MD5 (file intero)": hashlib.md5(raw).hexdigest(),
                    "SHA-256 (file intero)": hashlib.sha256(raw).hexdigest(),
                }
                dpi = img.info.get("dpi")
                if dpi and isinstance(dpi, tuple):
                    tech["DPI (x, y)"] = f"{dpi[0]}, {dpi[1]}"

                sections["Panoramica tecnica (OSINT)"] = tech
                sections["Fingerprint visivo (duplicati / varianti)"] = _visual_hashes(img)

                pinfo = _pillow_image_info(img)
                if pinfo:
                    sections["Info contenitore (PNG/JPEG chunks, ICC, …)"] = pinfo

                if pillow_exif is not None:
                    ptab = _pillow_exif_table(pillow_exif)
                    if ptab:
                        sections["EXIF / IPTC (lettura Pillow)"] = ptab

                xmp_tab = _xmp_from_image(img)
                if xmp_tab:
                    sections["XMP (Adobe / Dublin Core, estratto)"] = xmp_tab
                elif getattr(img, "getxmp", None):
                    messages.append("XMP: presente ma non parsabile automaticamente; controlla i chunk in 'Info contenitore'.")

        except UnidentifiedImageError:
            return ExifAnalysisResult(error="Formato immagine non supportato o file danneggiato.")

        tags_exifread = exifread.process_file(BytesIO(raw), details=True)
        lat = lon = alt_m = None

        if tags_exifread:
            sections["EXIF / MakerNote (exifread, dettagliato)"] = _exifread_tags_to_dict(tags_exifread)
            lat, lon, alt_m = _extract_gps_from_exifread(tags_exifread)
        else:
            messages.append("exifread: nessun blocco EXIF rilevato (comune su PNG senza EXIF o export social).")

        # GPS di riserva da Pillow se mancante
        if (lat is None or lon is None) and pillow_exif is not None:
            plat, plon, palt = _gps_from_pillow_exif(pillow_exif)
            if plat is not None and plon is not None:
                lat, lon = plat, plon
                if alt_m is None:
                    alt_m = palt
                messages.append("GPS ricavato da Pillow (IFD GPS) perché mancante o incompleto in exifread.")

        fmap: folium.Map | None = None
        if lat is not None and lon is not None:
            extra = []
            if alt_m is not None:
                extra.append(f"Alt: {alt_m:.1f} m")
            fmap = _build_folium_map(lat, lon, alt_m, extra)
        else:
            messages.append("Coordinate GPS non presenti o non decifrabili.")

        if not sections.get("EXIF / MakerNote (exifread, dettagliato)") and not sections.get("EXIF / IPTC (lettura Pillow)"):
            messages.append("Nessun metadato EXIF strutturato: l'immagine potrebbe essere stata ripulita o esportata senza metadati.")

        return ExifAnalysisResult(
            sections=sections,
            latitude=lat,
            longitude=lon,
            altitude_m=alt_m,
            folium_map=fmap,
            messages=messages,
        )

    except OSError as e:
        return ExifAnalysisResult(error=f"Errore di lettura del file: {e}")
    except Exception as e:  # noqa: BLE001
        return ExifAnalysisResult(error=f"Errore durante l'analisi: {e}")
    finally:
        if close_after and stream is not None:
            try:
                stream.close()
            except OSError:
                pass
