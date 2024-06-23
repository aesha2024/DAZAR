from flask import Flask, render_template, request, jsonify
import requests
import time


app = Flask(__name__)

API_KEY = '768ef179c15c9d463b7d194f0556d164c1fb2cb9097b884e14657f726123afe7'  # ضع هنا مفتاح API الخاص بك من VirusTotal

@app.route('/')
def index():
    return render_template('index.html')
    image_filename = 'static/11.jpg'  # تأكد من وجود الصورة في هذا المسار
    return render_template('index.html', image_filename=image_filename)

@app.route('/upload', methods=['POST'])
def upload():
    uploaded_files = request.files.getlist('file')
    results = []
    for file in uploaded_files:
        files = {'file': (file.filename, file.stream, file.content_type)}
        response = requests.post(
            'https://www.virustotal.com/api/v3/files',
            headers={'x-apikey': API_KEY},
            files=files
        )
        if response.status_code == 200:
            file_id = response.json().get('data', {}).get('id')
            if file_id:
                # الانتظار قليلاً قبل طلب تقرير الفحص
                time.sleep(30)
                report = requests.get(
                    f'https://www.virustotal.com/api/v3/analyses/{file_id}',
                    headers={'x-apikey': API_KEY}
                )
                if report.status_code == 200:
                    results.append(report.json())
        else:
            results.append({'error': 'Failed to upload file'})
    return jsonify(results)

@app.route('/scan', methods=['POST'])
def scan():
    links = request.form.get('link', '').split(',')
    results = []
    for link in links:
        response = requests.post(
            'https://www.virustotal.com/api/v3/urls',
            headers={'x-apikey': API_KEY},
            data={'url': link.strip()}
        )
        if response.status_code == 200:
            url_id = response.json().get('data', {}).get('id')
            if url_id:
                # الانتظار قليلاً قبل طلب تقرير الفحص
                time.sleep(30)
                report = requests.get(
                    f'https://www.virustotal.com/api/v3/analyses/{url_id}',
                    headers={'x-apikey': API_KEY}
                )
                if report.status_code == 200:
                    results.append(report.json())
        else:
            results.append({'error': f'Failed to scan link: {link}'})
    return jsonify(results)

@app.route('/scan_ip', methods=['POST'])
def scan_ip():
    ip_addresses = request.form.get('ip', '').split(',')
    results = []
    for ip in ip_addresses:
        response = requests.get(
            f'https://www.virustotal.com/api/v3/ip_addresses/{ip.strip()}',
            headers={'x-apikey': API_KEY}
        )
        if response.status_code == 200:
            results.append(response.json())
        else:
            results.append({'error': f'Failed to scan IP: {ip}'})
    return jsonify(results)

if __name__ == '__main__':
    app.run(debug=True)