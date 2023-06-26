from flask import Flask, render_template, request
import requests
import json

app = Flask(__name__)

# Замените YOUR_API_KEY на ваш API-ключ от VirusTotal
API_KEY = '46f9a258594c65c9e14542878cc075302ad09b1d8fdec401efd009fcc41189ae'

# Определяем функцию для отправки файла на проверку в VirusTotal
def scan_file(file_path):
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    params = {'apikey': API_KEY}
    files = {'file': (file_path, open(file_path, 'rb'))}
    response = requests.post(url, files=files, params=params)
    return response.json()

# Определяем функцию для получения результатов проверки файла в VirusTotal
def get_report(resource):
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': API_KEY, 'resource': resource}
    response = requests.get(url, params=params)
    return response.json()

# Определяем маршрут для загрузки файла и проверки его на вирусы
@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # Получаем загруженный файл
        file = request.files['file']
        # Сохраняем файл на диск
        file.save(file.filename)
        # Отправляем файл на проверку в VirusTotal
        response = scan_file(file.filename)
        # Получаем идентификатор ресурса для получения результатов проверки
        resource = response['resource']
        # Получаем результаты проверки файла в VirusTotal
        report = get_report(resource)
        # Отображаем результаты проверки на странице
        if report['response_code'] == 0:
            return render_template('result.html', message='Ошибка при проверке файла')
        elif report['positives'] == 0:
            return render_template('result.html', message='Файл не содержит вирусов')
        else:
            virus_names = [virus_name for virus_name in report['scans'] if report['scans'][virus_name]['detected']]
            return render_template('result.html', message='Файл содержит вирусы', virus_names=virus_names)
    else:
        return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)