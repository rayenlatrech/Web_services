from flask import Flask, jsonify, request
import requests
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity


app = Flask(__name__)

app.config['SECRET_KEY'] = 'your_secret_key'

jwt_manager = JWTManager(app)


def authenticate(username, password):
    try:
        conn = sqlite3.connect('user_data.db')
        cursor = conn.cursor()

        cursor.execute(
            "SELECT id, username, password_hash FROM users WHERE username=?", (username,))
        user = cursor.fetchone()

        conn.close()

        if user and check_password_hash(user[2], password):
            return {'user_id': user[0], 'username': user[1]}, True
        else:
            return None, False
    except sqlite3.Error as e:
        print(f'Error: {e}')
        return None, False


@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return jsonify({'message': 'Username and password are required!'}), 400

        user, is_authenticated = authenticate(username, password)

        if is_authenticated:
            access_token = create_access_token(identity=user['username'])
            return jsonify({'message': 'Login successful!', 'access_token': access_token})
        else:
            return jsonify({'message': 'Invalid username or password'}), 401
    except Exception as e:
        return jsonify({'message': f'Error: {e}'}), 500


@app.route('/user/delete/<username>', methods=['DELETE'])
@jwt_required()
def delete_user(username):
    current_user = get_jwt_identity()
    try:
        conn = sqlite3.connect('user_data.db')
        cursor = conn.cursor()

        cursor.execute("DELETE FROM users WHERE username=?", (username,))
        conn.commit()
        conn.close()

        return jsonify({'message': f'User {username} deleted'})
    except sqlite3.Error as e:
        return jsonify({'message': f'Error: {e}'})


@app.route('/update_portfolio', methods=['POST'])
@jwt_required()
def update_portfolio():
    current_user = get_jwt_identity()
    try:
        data = request.get_json()
        transaction_type = data.get('transaction_type')
        coin_name = data.get('coin_name')
        quantity = data.get('quantity')
        username = data.get('username')

        if not transaction_type or not coin_name or not quantity or not username:
            return jsonify({'message': 'Incomplete transaction data!'}), 400

        conn = sqlite3.connect('user_data.db')
        cursor = conn.cursor()

        cursor.execute(
            "SELECT portfolio FROM users WHERE username=?", (username,))
        user_portfolio = cursor.fetchone()[0]
        print(f"User Portfolio: {user_portfolio}")

        if transaction_type == 'purchase':
            if user_portfolio is None:
                user_portfolio = f"{coin_name}: {quantity}"
            else:
                coins = [line.split(': ')[0]
                         for line in user_portfolio.split('\n')]
                if coin_name in coins:
                    current_qty = float(user_portfolio.split(
                        '\n')[coins.index(coin_name)].split(': ')[1])
                    new_qty = current_qty + float(quantity)
                    user_portfolio = user_portfolio.replace(
                        f"{coin_name}: {current_qty}", f"{coin_name}: {new_qty}")
                else:
                    user_portfolio += f"\n{coin_name}: {quantity}"

        elif transaction_type == 'sell':
            if user_portfolio is None or coin_name not in user_portfolio:
                return jsonify({'message': 'Coin not found in portfolio!'}), 400

            current_qty = float(user_portfolio.split('\n')[[line.split(': ')[
                                0] for line in user_portfolio.split('\n')].index(coin_name)].split(': ')[1])
            if current_qty >= float(quantity):
                new_qty = current_qty - float(quantity)
                user_portfolio = user_portfolio.replace(
                    f"{coin_name}: {current_qty}", f"{coin_name}: {new_qty}")
            else:
                return jsonify({'message': 'Insufficient quantity to sell!'}), 400

        cursor.execute(
            "UPDATE users SET portfolio=? WHERE username=?", (user_portfolio, username))

        transaction_log = f"{coin_name}: {quantity} {transaction_type.capitalize()}"
        cursor.execute("UPDATE users SET transactions = COALESCE(transactions || '\n' || ?, ?) WHERE username = ?",
                       (transaction_log, transaction_log, username))

        conn.commit()
        conn.close()

        return jsonify({'message': 'Portfolio updated successfully!'})

    except sqlite3.Error as e:
        return jsonify({'message': f'Database error: {e}'}), 500
    except Exception as e:
        return jsonify({'message': f'Error: {e}'}), 500


@app.route('/portfolio_value/<username>', methods=['GET'])
@jwt_required()
def get_portfolio_value(username):

    try:
        conn = sqlite3.connect('user_data.db')
        cursor = conn.cursor()

        cursor.execute(
            "SELECT portfolio FROM users WHERE username=?", (username,))
        user_portfolio = cursor.fetchone()

        conn.close()

        if user_portfolio:
            user_portfolio = user_portfolio[0]

            if user_portfolio:
                print(f"User Portfolio: {user_portfolio}")  

                portfolio_coins = [line.split(': ')[0]
                                   for line in user_portfolio.split('\n')]
                coin_ids = ','.join([coin.lower() for coin in portfolio_coins])

                print(f"Coin IDs: {coin_ids}")  

                url = f'https://api.coingecko.com/api/v3/simple/price?ids={coin_ids}&vs_currencies=usd'
                response = requests.get(url)

                if response.status_code == 200:
                    current_prices = response.json()
                    total_portfolio_value_usd = 0
                    coin_values = []

                    for coin_name in portfolio_coins:
                        coin = coin_name.strip()
                        if coin.lower() in current_prices:
                            current_price = current_prices[coin.lower()]['usd']
                            quantity = float(user_portfolio.split(
                                '\n')[portfolio_coins.index(coin_name)].split(': ')[1])
                            amount_in_usd = quantity * current_price
                            total_portfolio_value_usd += amount_in_usd

                            coin_values.append({
                                'coin': coin,
                                'quantity': quantity,
                                'value_usd': amount_in_usd
                            })
                    return jsonify({
                        'coin_values': coin_values,
                        'total_portfolio_value_usd': total_portfolio_value_usd
                    })
                else:
                    return jsonify({'message': 'Failed to fetch current prices from CoinGecko'})
            else:
                return jsonify({'message': 'Empty portfolio for the user'})
        else:
            return jsonify({'message': 'User not found'})
    except Exception as e:
        print(f'Error fetching portfolio: {e}')
        return jsonify({'message': 'Error fetching portfolio'})


@app.route('/compare_currencies', methods=['GET'])
@jwt_required()
def compare_currencies():

    try:
        coins = request.args.get('coins').split(',')

        comparison_data = []

        for coin_symbol in coins:
            coin_data = get_coin_data(coin_symbol.strip())
            if coin_data:
                comparison_data.append({
                    'name': coin_data['name'],
                    'symbol': coin_data['symbol'],
                    'market_cap': coin_data['market_data']['market_cap']['usd'],
                    'circulating_supply': coin_data['market_data']['circulating_supply'],
                    'total_supply': coin_data['market_data']['total_supply'],
                    'max_supply': coin_data['market_data']['max_supply'],
                    'ath': coin_data['market_data']['ath']['usd'],
                    'volume_24h': coin_data['market_data']['total_volume']['usd'],
                    'price_change_24h': coin_data['market_data']['price_change_percentage_24h'],
                    'price_change_7d': coin_data['market_data']['price_change_percentage_7d'],
                    'price_change_30d': coin_data['market_data']['price_change_percentage_30d'],



                })

        return jsonify({'comparison_data': comparison_data})

    except Exception as e:
        return jsonify({'message': f'Error: {e}'}), 500


def get_coin_data(coin_symbol):
    try:
        url = f'https://api.coingecko.com/api/v3/coins/{coin_symbol.lower()}?localization=false'
        response = requests.get(url)

        if response.status_code == 200:
            return response.json()
        else:
            return None
    except Exception as e:
        print(f'Error fetching coin data: {e}')
        return None


@app.route('/change_password', methods=['POST'])
@jwt_required()
def change_password():
    try:
        current_user = get_jwt_identity()

        data = request.get_json()
        current_password = data.get('current_password')
        new_password = data.get('new_password')

        if not current_password or not new_password:
            return jsonify({'message': 'Current and new passwords are required!'}), 400

        user, is_authenticated = authenticate(current_user, current_password)

        if is_authenticated:
            conn = sqlite3.connect('user_data.db')
            cursor = conn.cursor()

            hashed_new_password = generate_password_hash(new_password)
            cursor.execute(
                "UPDATE users SET password_hash=? WHERE username=?", (hashed_new_password, current_user))
            conn.commit()
            conn.close()

            return jsonify({'message': 'Password changed successfully'})
        else:
            return jsonify({'message': 'Invalid current password'}), 401
    except Exception as e:
        return jsonify({'message': f'Error: {e}'}), 500


if __name__ == '__main__':
    app.run(debug=True)
