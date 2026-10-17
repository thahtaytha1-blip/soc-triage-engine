import os
from google import genai

client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])

response = client.models.generate_content(
    model="gemini-3.8-flash",
    contents="Respond with: 'SOC Triage Engine Online (100% Free)!'"
)

print(response.text)