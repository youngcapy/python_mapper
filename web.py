from flask import Flask, render_template, request, redirect, url_for, flash
import psycopg2
import psycopg2.extras
import json
import os

PG_CONN = {
    "host": "127.0.0.1",
    "port": 5432,
    "dbname": "linktelligence",
    "user": "postgres",
    "password": "admin",
}

app = Flask(__name__)
app.secret_key = "change_me"   # для flash-сообщений

def get_conn():
    return psycopg2.connect(**PG_CONN)

def get_table_list():
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute("""
            SELECT tablename
            FROM pg_tables
            WHERE schemaname = 'public'
            ORDER BY tablename;
        """)
        return [r[0] for r in cur.fetchall()]

def get_table_columns(table):
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(f"""
            SELECT column_name
            FROM information_schema.columns
            WHERE table_schema = 'public'
              AND table_name = %s
            ORDER BY ordinal_position;
        """, (table,))
        return [r[0] for r in cur.fetchall()]

def get_table_data(table, limit=200):
    with get_conn() as conn, conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
        cur.execute(f'SELECT * FROM "{table}" ORDER BY id LIMIT %s;', (limit,))
        rows = cur.fetchall()
        cols = [d.name for d in cur.description]
    return cols, rows

@app.route("/", methods=["GET", "POST"])
def index():
    tables = get_table_list()
    selected = request.values.get("table") or (tables[0] if tables else None)
    cols, rows = [], []
    if selected:
        cols, rows = get_table_data(selected)
    return render_template("index.html", tables=tables,
                           selected=selected, cols=cols, rows=rows)

# ---- Удаление таблицы ----
@app.post("/drop_table")
def drop_table():
    table = request.form.get("table")
    if not table:
        return redirect(url_for("index"))
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(f'DROP TABLE IF EXISTS "{table}" CASCADE;')
    flash(f"Таблица {table} удалена")
    return redirect(url_for("index"))

# ---- Удаление строки по id ----
@app.post("/delete_row")
def delete_row():
    table = request.form.get("table")
    row_id = request.form.get("row_id")
    if not (table and row_id):
        return redirect(url_for("index", table=table))
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(f'DELETE FROM "{table}" WHERE id = %s;', (row_id,))
    flash(f"Строка id={row_id} удалена из {table}")
    return redirect(url_for("index", table=table))

# ---- Редактирование строки (простое) ----
@app.post("/edit_row")
def edit_row():
    table = request.form.get("table")
    row_id = request.form.get("row_id")
    node_ip = request.form.get("node_ip")
    node_type = request.form.get("node_type")
    open_port_count = request.form.get("open_port_count")

    if not (table and row_id):
        return redirect(url_for("index", table=table))

    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            f'''UPDATE "{table}"
                SET node_ip = %s,
                    node_type = %s,
                    open_port_count = %s
              WHERE id = %s;''',
            (node_ip, node_type, int(open_port_count), row_id)
        )
    flash(f"Строка id={row_id} обновлена")
    return redirect(url_for("index", table=table))

# ---- Импорт JSON в выбранную таблицу ----
@app.post("/import_json")
def import_json():
    table = request.form.get("table")
    file = request.files.get("json_file")
    if not (table and file and file.filename):
        flash("Укажите таблицу и JSON‑файл")
        return redirect(url_for("index", table=table))

    data = json.load(file)
    scan_time = data.get("scan_time")
    nodes = data.get("nodes", [])

    with get_conn() as conn, conn.cursor() as cur:
        # гарантируем схему таблицы
        cur.execute(f"""
            CREATE TABLE IF NOT EXISTS "{table}" (
              id SERIAL PRIMARY KEY,
              scan_time TIMESTAMPTZ NOT NULL,
              node_ip inet NOT NULL,
              node_type text NOT NULL,
              open_ports integer[] NOT NULL,
              open_port_count integer NOT NULL
            );
        """)
        for n in nodes:
            cur.execute(
                f'''INSERT INTO "{table}"
                    (scan_time, node_ip, node_type, open_ports, open_port_count)
                    VALUES (%s, %s, %s, %s, %s);''',
                (scan_time, n["id"], n["type"],
                 n.get("open_ports", []), n.get("open_port_count", 0))
            )
    flash(f"Импортировано {len(nodes)} узлов в таблицу {table}")
    return redirect(url_for("index", table=table))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
