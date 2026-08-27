import customtkinter as ctk
import joblib
import re
from urllib.parse import urlparse
from tkinter import filedialog
from PIL import Image

# -----------------------
# إعدادات البرنامج
# -----------------------
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# -----------------------
# تحميل النموذج
# -----------------------
model = joblib.load("phishing_model.pkl")
vectorizer = joblib.load("vectorizer.pkl")

# -----------------------
# إنشاء النافذة
# -----------------------
app = ctk.CTk()
app.title("CyberAI Guard")
app.geometry("750x850")
app.minsize(900, 950)
app.resizable(True, True) 
                                                 
# -----------------------
# الشعار
# -----------------------
logo = ctk.CTkImage(
    light_image=Image.open("logo.png"),
    dark_image=Image.open("logo.png"),
    size=(100,100)                               
)

logo_label = ctk.CTkLabel(
    app,
    image=logo,
    text=""
)
logo_label.pack(pady=(10,3))       

# -----------------------
# العنوان
# -----------------------
title = ctk.CTkLabel(
    app,
    text="CyberAI Guard",
    font=("Segoe UI", 34, "bold"),
    text_color="#4DA6FF"
)
title.pack(pady=(0,5))

subtitle = ctk.CTkLabel(
    app,
    text="AI-Powered Phishing Message Detector",
    font=("Segoe UI",16),
    text_color="lightgray"
)
subtitle.pack(pady=(0,8))

# -----------------------
# إدخال الرسالة
# -----------------------
input_label = ctk.CTkLabel(
    app,
    text="📩 Enter Message",
    font=("Segoe UI",18,"bold")
)
input_label.pack()

textbox = ctk.CTkTextbox(
    app,
    width=700,
    height=120,
    font=("Segoe UI",16),
    corner_radius=15,
    border_width=2,
    border_color="#3399FF"
)
textbox.pack(pady=5) 

# -----------------------
# النتيجة
# -----------------------
result = ctk.CTkLabel(
    app,
    text="",
    font=("Segoe UI", 17),
    justify="left",
    wraplength=650,
    height=180
)
result.pack(pady=5) 

# -----------------------
# History
# -----------------------
history_label = ctk.CTkLabel(
    app,
    text="📜 Analysis History",
    font=("Segoe UI",16,"bold")
)
history_label.pack()

history_box = ctk.CTkTextbox(
    app,
    width=700,
    height=45,
    font=("Segoe UI",14)
)
history_box.pack(pady=2)
history_box.configure(state="disabled")

# -----------------------
# شريط الثقة
# -----------------------
confidence_bar = ctk.CTkProgressBar(
    app,
    width=600
)
confidence_bar.pack(pady=5)
confidence_bar.set(0) 
# -----------------------
# زر المسح
# -----------------------
def clear_text():
    textbox.delete("1.0", "end")
    result.configure(text="")
    confidence_bar.set(0)

    history_box.configure(state="normal")
    history_box.delete("1.0", "end")
    history_box.configure(state="disabled")


# -----------------------
# تحليل الرسالة
def analyze_url(message):

    urls = re.findall(r'https?://[^\s]+|www\.[^\s]+', message)

    if not urls:
        return {
            "has_url": False,
            "suspicious": False,
            "reasons": []
        }

    reasons = []

    for url in urls:
        check_url = url.lower()

        if "@" in check_url:
            reasons.append("الرابط يحتوي على @")

        if "login" in check_url:
            reasons.append("الرابط يحتوي على كلمة login")

        if "verify" in check_url:
            reasons.append("الرابط يحتوي على كلمة verify")

        if "free" in check_url:
            reasons.append("الرابط يحتوي على كلمة free")

        if len(url) > 100:
            reasons.append("الرابط طويل بشكل غير طبيعي")

        parsed = urlparse(
            url if url.startswith("http") else "https://" + url
        )

        if parsed.hostname and parsed.hostname.count(".") >= 3:
            reasons.append("النطاق يحتوي على نطاقات فرعية متعددة")

    return {
        "has_url": True,
        "suspicious": len(reasons) > 0,
        "reasons": reasons
    }                                          
def check_message():

    message = textbox.get("1.0", "end").strip()

    if message == "":
        result.configure(
            text="⚠ Please enter a message first.",
            text_color="orange"
        )
        confidence_bar.set(0)       
        return

    # -----------------------
    # تحليل الرسالة بالـ AI
    # -----------------------

    message_vector = vectorizer.transform([message])

    prediction = model.predict(message_vector)
    probability = model.predict_proba(message_vector)

    # احتمالات Safe و Phishing
    safe_probability = probability[0][0] * 100
    phishing_probability = probability[0][1] * 100

    # أعلى احتمال = Confidence
    confidence = max(
        safe_probability,
        phishing_probability
    )

    confidence_bar.set(confidence / 100)

    # -----------------------
    # تحديد مستوى الخطورة
    # حسب احتمال التصيد
    # -----------------------

    if phishing_probability >= 80:
        risk = "🔴 VERY HIGH"

    elif phishing_probability >= 60:
        risk = "🟠 HIGH"

    elif phishing_probability >= 40:
        risk = "🟡 MEDIUM"

    else:
        risk = "🟢 LOW"

    # -----------------------
    # تحليل الرابط
    # -----------------------

    url_result = analyze_url(message)

    # -----------------------
    # Phishing
    # -----------------------

    if prediction[0] == 1:

        report = (
            f"🛡 Analysis Result\n"
            f"🚨 Phishing Message\n"
            f"🎯 Confidence: {confidence:.2f}%\n"
            f"⚠ Risk Level: {risk}\n"
        )

        if url_result["has_url"]:

            report += "🔗 URL DETECTED\n"

            if url_result["suspicious"]:

                report += "⚠ Suspicious URL\n"

                for reason in url_result["reasons"][:2]:
                    report += f"• {reason}\n"

            else:
                report += "✅ No obvious URL indicators detected.\n"

        report += "🛡 Action: Do not click suspicious links."

        result.configure(
            text=report,
            text_color="red"
        )

        # -----------------------
        # History
        # -----------------------

        history_box.configure(state="normal")

        history_box.insert(
            "end",
            f"[PHISHING] {confidence:.2f}% | {risk}\n"
        )

        history_box.configure(state="disabled")

    # -----------------------
    # Safe
    # -----------------------

    else:

        report = (
            f"🛡 Analysis Result\n"
            f"✅ Safe Message\n"
            f"🎯 Confidence: {confidence:.2f}%\n"
            f"🟢 Risk Level: {risk}\n"
        )

        if url_result["has_url"]:

            report += "🔗 URL DETECTED\n"

            if url_result["suspicious"]:

                report += "⚠ Suspicious URL\n"

                for reason in url_result["reasons"][:2]:
                    report += f"• {reason}\n"

            else:
                report += "✅ No obvious URL indicators detected.\n"

        report += "🛡 Action: Message appears safe."

        result.configure(
            text=report,
            text_color="green"
        )

        # -----------------------
        # History
        # -----------------------

        history_box.configure(state="normal")

        history_box.insert(
            "end",
            f"[SAFE] {confidence:.2f}% | {risk}\n"
        )

        history_box.configure(state="disabled")
# تصدير التقرير
# -----------------------
def export_report():

    report = result.cget("text")

    if report == "":
        return

    file = filedialog.asksaveasfilename(
        defaultextension=".txt",
        filetypes=[("Text File", "*.txt")],
        title="Save Report"
    )

    if file:
        with open(file, "w", encoding="utf-8") as f:
            f.write("CyberAI Guard Report\n")
            f.write("=" * 40 + "\n\n")

            f.write("Message:\n")
            f.write(textbox.get("1.0", "end"))

            f.write("\n\n")
            f.write(report)


# -----------------------
# الأزرار
# -----------------------
button_frame = ctk.CTkFrame(app, fg_color="transparent")
button_frame.pack(pady=(0,2))

analyze_btn = ctk.CTkButton(
    button_frame,
    text="🔍 Analyze",
    width=180,
    height=45,
    font=("Segoe UI", 16, "bold"),
    fg_color="#0078D7",
    hover_color="#005EA6",
    corner_radius=12,
    command=check_message
)
analyze_btn.grid(row=0, column=0, padx=10)

clear_btn = ctk.CTkButton(
    button_frame,
    text="🗑 Clear",
    width=180,
    height=45,
    font=("Segoe UI", 16, "bold"),
    fg_color="gray30",
    hover_color="gray20",
    corner_radius=12,
    command=clear_text
)
clear_btn.grid(row=0, column=1, padx=10)

export_btn = ctk.CTkButton(
    button_frame,
    text="📄 Export Report",
    width=180,
    height=45,
    font=("Segoe UI", 16, "bold"),
    corner_radius=12,
    command=export_report
)
export_btn.grid(row=0, column=2, padx=10)      
# -----------------------
# تشغيل البرنامج
# -----------------------
app.mainloop()     