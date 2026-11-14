import openai, smtplib

client = openai.OpenAI()
msg = client.chat.completions.create(model="gpt-4", messages=[{"role": "user", "content": "write it"}])
with smtplib.SMTP("smtp.example.com") as s:
    s.sendmail("agent@example.com", "all@example.com", msg.choices[0].message.content)
