from flask import Flask, render_template, request
from subprocess import check_output, CalledProcessError
import pandas as pd
import io

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        input_type = request.form['input_type']
        input_data = request.form['input_data']
        output_type = request.form['output_type']

        try:
            if input_type == 'single':
                output = check_output(['python3', 'spoofy.py', '-d', input_data, '-o', output_type])
            elif input_type == 'list':
                output = check_output(['python3', 'spoofy.py', '-iL', input_data, '-o', output_type])
            else:
                return render_template('index.html', error='Invalid input type.')

            if output_type == 'xls':
                df = pd.read_excel(io.BytesIO(output))
                output_data = df.to_html(index=False)
            else:
                output_data = output.decode('utf-8')

            return render_template('index.html', output=output_data)
        except CalledProcessError as e:
            return render_template('index.html', error=e.output.decode('utf-8'))
    else:
        return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)