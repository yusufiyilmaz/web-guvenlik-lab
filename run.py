"""Uygulamayı başlatır.

    python run.py --mode vulnerable    # http://127.0.0.1:5000
    python run.py --mode secure        # http://127.0.0.1:5001

Her başlatmada veritabanı sahte verilerle sıfırlanır.
Uygulama yalnızca 127.0.0.1'e bağlanır; ağdaki başka cihazlardan erişilemez.
"""
import argparse

from notes_app import create_app

PORTS = {"vulnerable": 5000, "secure": 5001}

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Notes — web security lab")
    ap.add_argument("--mode", choices=PORTS, default="secure")
    args = ap.parse_args()
    create_app(args.mode).run(host="127.0.0.1", port=PORTS[args.mode], debug=False)
