@app.route('/dashboard')
# def dashboard():
#     if 'user_id' in session:
#         user_id = session['user_id']
#         cursor = mysql.connection.cursor()
#         cursor.execute("SELECT * FROM users WHERE id=%s", (user_id,))
#         user = cursor.fetchone()
#         cursor.close()
        
#         if user:
#             # Calculate network state
#             total_packets, unique_source_ips, unique_destination_ips, total_nodes = calculate_network_state()
#             return render_template('dashboard.html', user=user,
#                                    total_packets=total_packets,
#                                    unique_source_ips=unique_source_ips,
#                                    unique_destination_ips=unique_destination_ips,
#                                    total_nodes=total_nodes)
#     return redirect(url_for('login'))