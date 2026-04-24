import streamlit as st
import pandas as pd
import json
import hashlib
import os
import re
import joblib
from datetime import datetime

# CONFIG
st.set_page_config(page_title="Prompt Injection Detection System", layout="wide")

# LOAD MODEL
model = joblib.load("data/svm_model.pkl")
vectorizer = joblib.load("data/tfidf.pkl")

# GEMINI
import google.generativeai as genai
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
model_gemini = genai.GenerativeModel("gemini-2.5-flash")

# FILE HELPERS
def load_users():
    return json.load(open("users.json")) if os.path.exists("users.json") else {}

def save_users(users):
    json.dump(users, open("users.json", "w"))

def load_history():
    return json.load(open("history.json")) if os.path.exists("history.json") else {}

def save_history(user, prompt):
    history = load_history()
    history.setdefault(user, [])
    history[user].insert(0, prompt)
    history[user] = history[user][:20]
    json.dump(history, open("history.json", "w"))

def save_log(user, prompt, r, m, f, d):
    row = {
        "time": datetime.now(),
        "user": user,
        "prompt": prompt,
        "rule": r,
        "ml": m,
        "final": f,
        "decision": d
    }
    df = pd.DataFrame([row])

    if os.path.exists("logs.csv"):
        df_old = pd.read_csv("logs.csv")
        df = pd.concat([df_old, df])

    df.to_csv("logs.csv", index=False)

# AUTH
def hash_password(p):
    return hashlib.sha256(p.encode()).hexdigest()

users = load_users()

if "user" not in st.session_state:
    st.session_state.user = None

if "page" not in st.session_state:
    st.session_state.page = "login"

# =========================
# UPDATED RULE FILTER (5 CATEGORIES)
# =========================
class RuleFilter:
    def __init__(self):
        self.rules = {
            "override": [
                r"ignore instructions",
                r"disregard rules",
                r"override system"
            ],
            "extraction": [
                r"system prompt",
                r"hidden instructions",
                r"internal prompt"
            ],
            "role": [
                r"act as",
                r"you are now",
                r"pretend to be"
            ],
            "jailbreak": [
                r"bypass",
                r"jailbreak",
                r"disable safety"
            ],
            "sensitive": [
                r"api key",
                r"password",
                r"token",
                r"credentials"
            ]
        }

    def analyze(self, prompt):
        prompt = prompt.lower()
        score = 0

        for category in self.rules.values():
            for pattern in category:
                if re.search(pattern, prompt):
                    score += 20
                    break  # only one match per category

        return score

rule_detector = RuleFilter()

# DETECTION
def detect(prompt):
    rule = rule_detector.analyze(prompt)

    vec = vectorizer.transform([prompt])
    probs = model.predict_proba(vec)[0]
    ml = probs[list(model.classes_).index(1)] * 100

    final = max(rule, ml)

    if final >= 85:
        decision = "MALICIOUS"
    elif final >= 50:
        decision = "SUSPICIOUS"
    else:
        decision = "SAFE"

    return rule, ml, final, decision

# LOGIN
if st.session_state.page == "login":

    st.title("Prompt Injection Detection System")

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if username in users and users[username] == hash_password(password):
            st.session_state.user = username
            st.session_state.page = "dashboard"
            st.rerun()
        else:
            st.error("Invalid credentials")

    if st.button("Register"):
        st.session_state.page = "register"
        st.rerun()

# REGISTER
elif st.session_state.page == "register":

    st.title("Register")

    new_user = st.text_input("Username")
    new_pass = st.text_input("Password", type="password")

    if st.button("Create Account"):
        if new_user in users:
            st.error("User exists")
        else:
            users[new_user] = hash_password(new_pass)
            save_users(users)
            st.success("Account created")

    if st.button("Back"):
        st.session_state.page = "login"
        st.rerun()

# DASHBOARD
elif st.session_state.page == "dashboard":

    st.sidebar.title("🕒 History")

    history = load_history()

    if st.session_state.user in history:
        for h in history[st.session_state.user]:
            st.sidebar.markdown(f"- {h[:50]}...")
    else:
        st.sidebar.write("No history")

    if st.sidebar.button("Logout"):
        st.session_state.user = None
        st.session_state.page = "login"
        st.rerun()

    st.title("Prompt Injection Detection System")

    prompt = st.text_area("Enter your prompt")

    if st.button("Analyze"):

        r, m, f, d = detect(prompt)

        col1, col2, col3 = st.columns(3)
        col1.metric("Rule %", f"{r:.2f}")
        col2.metric("ML %", f"{m:.2f}")
        col3.metric("Final %", f"{f:.2f}")

        if d == "MALICIOUS":
            st.error("❌ Malicious Prompt BLOCKED")

        elif d == "SUSPICIOUS":
            st.warning("⚠️ Suspicious Prompt")
            st.info("Please rephrase your prompt.")

        else:
            st.success("✅ Safe Prompt ALLOWED")

            try:
                response = model_gemini.generate_content(prompt)
                st.subheader("🤖 Gemini Response")
                st.write(response.text)
            except Exception:
                st.warning("⚠️ Gemini API limit reached")

        save_log(st.session_state.user, prompt, r, m, f, d)
        save_history(st.session_state.user, prompt)