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

## Il Flusso dei Dati (Data Flow)

```text
[ Utente carica l'immagine ]
           │
           ▼
┌──────────────────────────────────────┐
│       main.py (Streamlit UI)         │ <── Gestisce lo stato e il layout
└──────────────────────────────────────┘
           │ (Passa i Byte grezzi)
           ▼
┌──────────────────────────────────────┐
│     core/exif_analyzer.py            │
│  1. Validazione (Pillow)             │
│  2. Hashing (MD5/SHA256 & ImageHash) │ <── Analisi in pipeline parallela
│  3. Estrazione EXIF & XMP            │
│  4. Calcolo GPS & Generazione Mappa  │
└──────────────────────────────────────┘
           │
           ▼ (Incapasula tutto in)
┌──────────────────────────────────────┐
│       ExifAnalysisResult             │ <── Oggetto dati tipizzato e stabile
└──────────────────────────────────────┘
           │
           ▼
┌──────────────────────────────────────┐
│       main.py (Rendering UI)         │
│  - Tabella sinistra (Dati ordinati)  │ <── Mostra i risultati all'utente
│  - Mappa destra (Componente HTML)     │
└──────────────────────────────────────┘
```
## Nota legale / privacy

Usa lo strumento solo su immagini che hai il diritto di analizzare. Coordinate e metadati possono essere assenti, errati o manipolati.
