from flask import render_template, Flask, request, jsonify
import re
from phisher import phisher_
from update_email_reputation import update_mutation

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index_page():
    if request.method == 'POST':
        global input_data
        input_data = request.form['input_data']
        
        try:
            phisher_data,performable_actions = phisher_(input_data)
            print('IN APP TRY : \nphisher_data:', performable_actions)
            if performable_actions == {}:
                performable_actions['clean'] = 'No action required'
        except:
            return 'Error in processing the input data'
        
        print('in app now: \nperformable_actions:', performable_actions)

        return render_template('index.html', 
                                result=phisher_data.get('FINAL_OUTPUT', "No output available"), 
                                email_body_result=phisher_data.get('email_body_result', "No email body available"),
                                performable_actions=performable_actions)

    else:
        return render_template('index.html', performable_actions = {'action': 'Performable actions will be displayed here'})


@app.route('/action', methods=['POST'])
def action():
    global input_data
    #print('\n\n\n\n\nINPUT DATA : ', input_data)

    data = request.get_json()
    actions_taken = data.get('actions_taken')
    #print("\n\nACTIONS TAKEN : ", actions_taken)
    severity_level = data.get('severity_level')

    #state = severity_level.split('_')
    #category =state[0].upper()
    #status=state[1].upper()
    #everity=state[2].upper()

    
    json_data, statuscode = update_mutation(input_data, severity_level)
    


    # Check for missing required fields
    if not actions_taken or not severity_level:
        return jsonify({"error": "Missing required fields"}), 400

    #print('ACTIONS RECEIVED:', actions_taken)
    #rint('SEVERITY LEVEL:', severity_level)

    return json_data, statuscode

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
