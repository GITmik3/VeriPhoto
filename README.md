# VeriPhoto

Strumento leggero di **Digital Forensics / OSINT** per analizzare immagini da fonti anonime: metadati (EXIF da più lettori, XMP, ICC), hash di file, fingerprint visivo e mappa GPS quando presente.

## Requisiti

- Python 3.10+ consigliato
- Dipendenze in `requirements.txt`

## Installazione

```bash
pip install -r requirements.txt
```

## Avvio (Streamlit)

```bash
python -m streamlit run main.py
```

Su Windows puoi usare anche `run.bat` se `streamlit` non è nel PATH.

## Struttura

- `main.py` — interfaccia Streamlit
- `core/exif_analyzer.py` — estrazione metadati e mappa Folium
- `core/__init__.py` — package `core`

## Nota legale / privacy

Usa lo strumento solo su immagini che hai il diritto di analizzare. Coordinate e metadati possono essere assenti, errati o manipolati.
