from flask import Blueprint

from api.utils import get_credentials, get_jwt, jsonify_data

health_api = Blueprint('health', __name__)


@health_api.route('/health', methods=['POST'])
def health():
    credentials = get_credentials()
    workspace_id = credentials.get('VAL1').split(':')[1]
    print(workspace_id)
    return jsonify_data({'status': 'ok'})
