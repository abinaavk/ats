import sqlite3
import os

# CONFIG
DB_FILE = "/home/gaia/ats/ats.db"

def import_legacy():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    services = [
        # SERVICE 1: PINNACLE API
        {
            "name": "pinnacle_api",  # Must match systemd service name exactly
            "port": 8081,
            "domain": "data.gaiasentinel.online",
            "storage_path": "/opt/extra1_1tb", # ATS expects /api/pinnacle_api inside here
            "repo_url": "git@github.com:Abinaav-K876/gok_pinnacle.git"
        },
        # SERVICE 2: GAIA SENTINEL (Main Site)
        {
            "name": "gaia_sentinel", # Must match systemd service name exactly
            "port": 8080,
            "domain": "gaiasentinel.online",
            "storage_path": "/opt", # ATS will look for /api/gaia_sentinel here
            "repo_url": "git@github.com:Abinaav-K876/gaia_sentinel.git"
        }
    ]

    print("--- IMPORTING LEGACY SERVICES ---")
    
    for svc in services:
        try:
            cursor.execute('''
                INSERT INTO services (name, port, domain, storage_path, repo_url, status)
                VALUES (?, ?, ?, ?, ?, 'active')
            ''', (svc['name'], svc['port'], svc['domain'], svc['storage_path'], svc['repo_url']))
            print(f"✅ Imported: {svc['name']}")
        except sqlite3.IntegrityError:
            print(f"⚠️  Skipped: {svc['name']} (Already in DB)")
        except Exception as e:
            print(f"❌ Error importing {svc['name']}: {e}")

    conn.commit()
    conn.close()
    print("---------------------------------")
    print("Import complete. You can now manage these in ATS.")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("❌ Run as root (sudo)")
    else:
        import_legacy()
