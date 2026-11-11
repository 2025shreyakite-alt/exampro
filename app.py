"""ExamPro - Flask + SQLite online examination system.
Run:  pip install -r requirements.txt && python app.py
Admin: admin@exampro.com / admin123   Student: student@exampro.com / student123"""
import sqlite3
from datetime import date, timedelta, datetime
from functools import wraps
from flask import (Flask, g, render_template, request, redirect, url_for,
                   session, jsonify, flash)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "change-this-secret-in-production"
DB = "exampro.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT, email TEXT UNIQUE,
  password TEXT, role TEXT DEFAULT 'student');
CREATE TABLE IF NOT EXISTS exams(id INTEGER PRIMARY KEY, title TEXT, subject TEXT,
  kind TEXT DEFAULT 'exam', duration INTEGER, pass_mark INTEGER DEFAULT 40,
  exam_date TEXT, published INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS questions(id INTEGER PRIMARY KEY, exam_id INTEGER
  REFERENCES exams(id) ON DELETE CASCADE, text TEXT, a TEXT, b TEXT, c TEXT, d TEXT, correct TEXT);
CREATE TABLE IF NOT EXISTS attempts(id INTEGER PRIMARY KEY, user_id INTEGER
  REFERENCES users(id) ON DELETE CASCADE, exam_id INTEGER REFERENCES exams(id) ON DELETE CASCADE,
  score INTEGER, total INTEGER, submitted_at TEXT);
CREATE TABLE IF NOT EXISTS answers(id INTEGER PRIMARY KEY, attempt_id INTEGER
  REFERENCES attempts(id) ON DELETE CASCADE, question_id INTEGER, choice TEXT);
"""

# ---------- database helpers ----------
def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d: d.close()

def q(sql, args=(), one=False):          # SELECT helper
    rows = db().execute(sql, args).fetchall()
    return (rows[0] if rows else None) if one else rows

def run(sql, args=()):                   # INSERT/UPDATE/DELETE helper
    cur = db().execute(sql, args); db().commit(); return cur.lastrowid

# ---------- role-based access ----------
def login_required(role=None):
    def deco(f):
        @wraps(f)
        def wrapper(*a, **k):
            if "uid" not in session:
                if request.path.startswith("/api"): return jsonify(error="Login required"), 401
                return redirect(url_for("login"))
            if role and session["role"] != role:
                if request.path.startswith("/api"): return jsonify(error="Forbidden"), 403
                return redirect(url_for("home"))
            return f(*a, **k)
        return wrapper
    return deco

# ---------- auth ----------
@app.route("/")
def home():
    if "uid" not in session: return redirect(url_for("login"))
    return redirect(url_for("admin" if session["role"] == "admin" else "dashboard"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = q("SELECT * FROM users WHERE email=?", (request.form["email"].strip().lower(),), True)
        if u and check_password_hash(u["password"], request.form["password"]):
            session.update(uid=u["id"], role=u["role"], name=u["name"])
            return redirect(url_for("home"))
        flash("Incorrect email or password.", "error")
    return render_template("login.html", mode="login")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name, email, pw = request.form["name"].strip(), request.form["email"].strip().lower(), request.form["password"]
        if not name or "@" not in email or len(pw) < 6:
            flash("Enter a name, a valid email and a password of 6+ characters.", "error")
        elif q("SELECT 1 FROM users WHERE email=?", (email,), True):
            flash("That email is already registered.", "error")
        else:   # role is ALWAYS 'student' here - admins can't self-register
            run("INSERT INTO users(name,email,password) VALUES(?,?,?)", (name, email, generate_password_hash(pw)))
            flash("Account created. Please log in.", "ok")
            return redirect(url_for("login"))
    return render_template("login.html", mode="register")

@app.route("/logout")
def logout():
    session.clear(); return redirect(url_for("login"))

# ---------- student pages ----------
@app.route("/dashboard")
@login_required("student")
def dashboard():
    uid = session["uid"]
    exams = q("SELECT * FROM exams WHERE published=1 ORDER BY exam_date")
    done = {r["exam_id"] for r in q("SELECT exam_id FROM attempts WHERE user_id=?", (uid,))}
    upcoming = [e for e in exams if e["id"] not in done and e["kind"] == "exam"]
    avg = q("SELECT AVG(score*100.0/total) a FROM attempts WHERE user_id=?", (uid,), True)["a"] or 0
    subj = q("""SELECT e.subject, AVG(a.score*100.0/a.total) p FROM attempts a
                JOIN exams e ON e.id=a.exam_id WHERE a.user_id=? GROUP BY e.subject""", (uid,))
    stats = dict(total=len(exams), done=len(done), upcoming=len(upcoming), avg=round(avg))
    return render_template("dashboard.html", stats=stats, upcoming=upcoming[:4], subj=subj,
                           dates=[e["exam_date"] for e in upcoming if e["exam_date"]])

@app.route("/exams")
@login_required("student")
def exams():
    kind = request.args.get("kind", "exam")
    rows = q("SELECT e.*, (SELECT COUNT(*) FROM questions WHERE exam_id=e.id) n, "
             "(SELECT COUNT(*) FROM attempts WHERE exam_id=e.id AND user_id=?) tries "
             "FROM exams e WHERE published=1 AND kind=? ORDER BY exam_date", (session["uid"], kind))
    return render_template("exams.html", rows=rows, kind=kind)

@app.route("/results")
@login_required("student")
def results():
    rows = q("""SELECT a.*, e.title, e.subject, e.pass_mark FROM attempts a JOIN exams e ON e.id=a.exam_id
                WHERE a.user_id=? ORDER BY a.id DESC""", (session["uid"],))
    return render_template("misc.html", page="results", rows=rows)

@app.route("/resources")
@login_required("student")
def resources():
    return render_template("misc.html", page="resources")

@app.route("/profile")
@login_required("student")
def profile():
    u = q("SELECT * FROM users WHERE id=?", (session["uid"],), True)
    n = q("SELECT COUNT(*) c FROM attempts WHERE user_id=?", (u["id"],), True)["c"]
    return render_template("misc.html", page="profile", u=u, n=n)

# ---------- taking an exam ----------
@app.route("/exam/<int:eid>")
@login_required("student")
def take_exam(eid):
    e = q("SELECT * FROM exams WHERE id=? AND published=1", (eid,), True)
    if not e: return redirect(url_for("exams"))
    qs = q("SELECT id,text,a,b,c,d FROM questions WHERE exam_id=?", (eid,))  # NOTE: 'correct' is never sent to the browser
    return render_template("exam.html", exam=dict(e), questions=[dict(x) for x in qs])

@app.post("/api/exam/<int:eid>/submit")
@login_required("student")
def submit(eid):
    ans = (request.get_json(silent=True) or {}).get("answers", {})
    qs = q("SELECT id, correct FROM questions WHERE exam_id=?", (eid,))
    score = sum(1 for x in qs if ans.get(str(x["id"])) == x["correct"])   # automatic evaluation
    aid = run("INSERT INTO attempts(user_id,exam_id,score,total,submitted_at) VALUES(?,?,?,?,?)",
              (session["uid"], eid, score, len(qs), datetime.now().strftime("%Y-%m-%d %H:%M")))
    for x in qs:
        run("INSERT INTO answers(attempt_id,question_id,choice) VALUES(?,?,?)", (aid, x["id"], ans.get(str(x["id"]))))
    return jsonify(url=url_for("result", aid=aid))

@app.route("/result/<int:aid>")
@login_required()
def result(aid):
    a = q("SELECT a.*, e.title, e.subject, e.pass_mark FROM attempts a JOIN exams e ON e.id=a.exam_id WHERE a.id=?", (aid,), True)
    if not a or (session["role"] != "admin" and a["user_id"] != session["uid"]): return redirect(url_for("home"))
    rev = q("""SELECT q.text,q.a,q.b,q.c,q.d,q.correct,x.choice FROM answers x
               JOIN questions q ON q.id=x.question_id WHERE x.attempt_id=?""", (aid,))
    pct = round(a["score"] * 100 / a["total"]) if a["total"] else 0
    skipped = sum(1 for r in rev if not r["choice"])
    wrong = len(rev) - a["score"] - skipped
    hist = q("SELECT score*100/total p FROM attempts WHERE user_id=? ORDER BY id", (a["user_id"],))
    return render_template("result.html", a=a, rev=rev, pct=pct, passed=pct >= a["pass_mark"],
                           wrong=wrong, skipped=skipped, hist=[h["p"] for h in hist])

# ---------- admin ----------
@app.route("/admin")
@login_required("admin")
def admin():
    return render_template("admin.html")

def exam_fields(d):
    return (d["title"].strip(), d["subject"].strip(), d["kind"], int(d["duration"]),
            int(d["pass_mark"]), d.get("exam_date") or None)

@app.get("/api/admin/exams")
@login_required("admin")
def a_exams():
    return jsonify([dict(r) for r in q("SELECT e.*, (SELECT COUNT(*) FROM questions WHERE exam_id=e.id) n FROM exams e ORDER BY id DESC")])

@app.post("/api/admin/exams")
@login_required("admin")
def a_exam_add():
    try: f = exam_fields(request.json)
    except (KeyError, ValueError): return jsonify(error="Fill in all exam fields correctly."), 400
    return jsonify(id=run("INSERT INTO exams(title,subject,kind,duration,pass_mark,exam_date) VALUES(?,?,?,?,?,?)", f))

@app.put("/api/admin/exams/<int:eid>")
@login_required("admin")
def a_exam_edit(eid):
    try: f = exam_fields(request.json)
    except (KeyError, ValueError): return jsonify(error="Fill in all exam fields correctly."), 400
    run("UPDATE exams SET title=?,subject=?,kind=?,duration=?,pass_mark=?,exam_date=? WHERE id=?", f + (eid,))
    return jsonify(ok=True)

@app.delete("/api/admin/exams/<int:eid>")
@login_required("admin")
def a_exam_del(eid):
    run("DELETE FROM exams WHERE id=?", (eid,)); return jsonify(ok=True)

@app.post("/api/admin/exams/<int:eid>/publish")
@login_required("admin")
def a_publish(eid):
    n = q("SELECT COUNT(*) c FROM questions WHERE exam_id=?", (eid,), True)["c"]
    cur = q("SELECT published FROM exams WHERE id=?", (eid,), True)["published"]
    if not cur and n == 0: return jsonify(error="Add at least one question before publishing."), 400
    run("UPDATE exams SET published=? WHERE id=?", (0 if cur else 1, eid)); return jsonify(published=not cur)

@app.get("/api/admin/exams/<int:eid>/questions")
@login_required("admin")
def a_qs(eid):
    return jsonify([dict(r) for r in q("SELECT * FROM questions WHERE exam_id=?", (eid,))])

def q_fields(d):
    v = [d[k].strip() for k in ("text", "a", "b", "c", "d")]
    if not all(v) or d["correct"] not in "ABCD" or not d["correct"]: raise ValueError
    return tuple(v) + (d["correct"],)

@app.post("/api/admin/exams/<int:eid>/questions")
@login_required("admin")
def a_q_add(eid):
    try: f = q_fields(request.json)
    except (KeyError, ValueError): return jsonify(error="Question, four options and the correct answer are required."), 400
    return jsonify(id=run("INSERT INTO questions(exam_id,text,a,b,c,d,correct) VALUES(?,?,?,?,?,?,?)", (eid,) + f))

@app.put("/api/admin/questions/<int:qid>")
@login_required("admin")
def a_q_edit(qid):
    try: f = q_fields(request.json)
    except (KeyError, ValueError): return jsonify(error="Question, four options and the correct answer are required."), 400
    run("UPDATE questions SET text=?,a=?,b=?,c=?,d=?,correct=? WHERE id=?", f + (qid,)); return jsonify(ok=True)

@app.delete("/api/admin/questions/<int:qid>")
@login_required("admin")
def a_q_del(qid):
    run("DELETE FROM questions WHERE id=?", (qid,)); return jsonify(ok=True)

@app.get("/api/admin/students")
@login_required("admin")
def a_students():
    return jsonify([dict(r) for r in q("""SELECT u.id,u.name,u.email,COUNT(a.id) attempts,
        ROUND(AVG(a.score*100.0/a.total)) avg FROM users u LEFT JOIN attempts a ON a.user_id=u.id
        WHERE u.role='student' GROUP BY u.id""")])

@app.delete("/api/admin/students/<int:uid>")
@login_required("admin")
def a_student_del(uid):
    run("DELETE FROM users WHERE id=? AND role='student'", (uid,)); return jsonify(ok=True)

@app.get("/api/admin/analytics")
@login_required("admin")
def a_analytics():
    per = q("""SELECT e.title, COUNT(a.id) n, ROUND(AVG(a.score*100.0/a.total)) avg,
        SUM(CASE WHEN a.score*100.0/a.total >= e.pass_mark THEN 1 ELSE 0 END) passed
        FROM exams e LEFT JOIN attempts a ON a.exam_id=e.id GROUP BY e.id""")
    res = q("""SELECT a.id,u.name,e.title,a.score,a.total,a.submitted_at,
        ROUND(a.score*100.0/a.total) pct, a.score*100.0/a.total >= e.pass_mark ok
        FROM attempts a JOIN users u ON u.id=a.user_id JOIN exams e ON e.id=a.exam_id ORDER BY a.id DESC""")
    return jsonify(per_exam=[dict(r) for r in per], results=[dict(r) for r in res])

# ---------- setup & sample data ----------
SAMPLE = {
 "Mathematics": [("What is 12 x 8?","86","96","108","92","B"), ("Solve: 2x + 6 = 14. x = ?","3","4","5","6","B"),
   ("What is the square root of 144?","10","11","12","14","C"), ("What is 15% of 200?","20","25","30","35","C")],
 "Science": [("Which gas do plants absorb?","Oxygen","Nitrogen","Carbon dioxide","Helium","C"),
   ("Chemical symbol for water?","H2O","CO2","NaCl","O2","A"), ("Which planet is the Red Planet?","Venus","Mars","Jupiter","Saturn","B"),
   ("Unit of force?","Joule","Watt","Newton","Pascal","C")],
 "English": [("Choose the synonym of 'rapid'.","Slow","Quick","Heavy","Quiet","B"),
   ("Plural of 'child'?","Childs","Childes","Children","Childrens","C"), ("Which is a noun?","Run","Happy","Quickly","Table","D"),
   ("Past tense of 'go'?","Goed","Gone","Went","Going","C")]}

def init_db():
    with sqlite3.connect(DB) as c:
        c.executescript(SCHEMA)
        if c.execute("SELECT COUNT(*) FROM users").fetchone()[0]: return
        c.execute("INSERT INTO users(name,email,password,role) VALUES('Administrator','admin@exampro.com',?,'admin')", (generate_password_hash("admin123"),))
        c.execute("INSERT INTO users(name,email,password) VALUES('Demo Student','student@exampro.com',?)", (generate_password_hash("student123"),))
        def add(title, subj, kind, dur, days, qs):
            eid = c.execute("INSERT INTO exams(title,subject,kind,duration,pass_mark,exam_date,published) VALUES(?,?,?,?,40,?,1)",
                (title, subj, kind, dur, str(date.today() + timedelta(days=days)))).lastrowid
            c.executemany("INSERT INTO questions(exam_id,text,a,b,c,d,correct) VALUES(?,?,?,?,?,?,?)", [(eid,) + x for x in qs])
        for i, (s, qs) in enumerate(SAMPLE.items()):
            add(f"{s} Term Exam", s, "exam", 10, 3 + i * 4, qs)
            add(f"{s} Practice Set", s, "practice", 5, 0, qs)
        add("Full Mock Test", "General", "mock", 15, 14, [x for v in SAMPLE.values() for x in v])

init_db()
if __name__ == "__main__":
    app.run(debug=True)
