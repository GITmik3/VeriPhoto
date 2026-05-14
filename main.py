"""
VeriPhoto — entry point Streamlit.

Caricamento immagine, analisi metadati orientata a OSINT (tecnica, EXIF, XMP, fingerprint, GPS).
"""

from __future__ import annotations

import streamlit as st
import streamlit.components.v1 as components

from core.exif_analyzer import analyze_exif

# Ordine schede più utile per chi fa OSINT (prima contesto file, poi dettaglio)
_SECTION_ORDER = [
    "Panoramica tecnica (OSINT)",
    "Fingerprint visivo (duplicati / varianti)",
    "Info contenitore (PNG/JPEG chunks, ICC, …)",
    "EXIF / IPTC (lettura Pillow)",
    "XMP (Adobe / Dublin Core, estratto)",
    "EXIF / MakerNote (exifread, dettagliato)",
]


def _ordered_section_keys(sections: dict[str, dict[str, str]]) -> list[str]:
    keys = list(sections.keys())
    head = [k for k in _SECTION_ORDER if k in sections]
    tail = sorted(k for k in keys if k not in head)
    return head + tail


def main() -> None:
    """Configura la pagina e il layout principale."""
    st.set_page_config(
        page_title="VeriPhoto",
        page_icon="🔍",
        layout="wide",
    )

    st.title("VeriPhoto")
    st.caption(
        "Digital Forensics / OSINT su immagini anonime: metadati multi-fonte, fingerprint visivo, "
        "EXIF/XMP e geolocalizzazione quando disponibile."
    )

    st.subheader("Carica un'immagine")
    uploaded = st.file_uploader(
        "Seleziona un file JPG o PNG",
        type=["jpg", "jpeg", "png", "webp"],
        help="Vengono analizzati contenitore, EXIF (Pillow + exifread), XMP, ICC e hash. "
        "Molte piattaforme rimuovono i metadati: assenza di dati è anch'essa un'informazione OSINT.",
    )

    if uploaded is None:
        st.info("Carica un'immagine per iniziare l'analisi.")
        return

    file_bytes = uploaded.getvalue()
    result = analyze_exif(file_bytes)

    if result.error:
        st.error(result.error)
        return

    if result.messages:
        with st.expander("Note e avvisi (contesto OSINT)", expanded=False):
            for m in result.messages:
                st.markdown(f"- {m}")

    col_left, col_right = st.columns([1.2, 1])

    with col_left:
        st.subheader("Risultati per sezione")
        if not result.sections:
            st.write("Nessuna sezione disponibile.")
        else:
            keys = _ordered_section_keys(result.sections)
            tabs = st.tabs(keys)
            for tab, section_name in zip(tabs, keys):
                with tab:
                    table = result.sections[section_name]
                    if not table:
                        st.caption("Nessun dato in questa sezione.")
                    else:
                        st.dataframe(
                            [{"Campo": k, "Valore": v} for k, v in table.items()],
                            use_container_width=True,
                            hide_index=True,
                        )

            with st.expander("Vista unica (tutti i campi concatenati)", expanded=False):
                merged = result.metadata
                st.dataframe(
                    [{"Campo": k, "Valore": v} for k, v in merged.items()],
                    use_container_width=True,
                    hide_index=True,
                )

    with col_right:
        st.subheader("Mappa GPS")
        if (
            result.folium_map is not None
            and result.latitude is not None
            and result.longitude is not None
        ):
            line = (
                f"**Latitudine:** `{result.latitude:.6f}` · **Longitudine:** `{result.longitude:.6f}`"
            )
            if result.altitude_m is not None:
                line += f" · **Altitudine (EXIF):** `{result.altitude_m:.1f} m`"
            st.markdown(line)
            st.caption(
                "Le coordinate provengono dai metadati del file: possono essere assenti, errate o "
                "manomesse. Usale come indizi, non come prova certa di luogo."
            )
            components.html(result.folium_map._repr_html_(), height=480, scrolling=True)
        else:
            st.write("Nessuna mappa disponibile (mancano coordinate GPS valide nei metadati).")


if __name__ == "__main__":
    main()
