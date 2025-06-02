"""
Comprehensive SQL mutation test file with various operations and edge cases
"""
import sqlite3
import pandas as pd

# Database connection setup
conn = sqlite3.connect(':memory:')
cursor = conn.cursor()

# 1. Basic SQL mutations - Direct string queries
cursor.execute("DELETE FROM users WHERE id = 1")  # CRITICAL severity
cursor.execute("UPDATE users SET name = 'John' WHERE id = 1")  # CRITICAL severity
cursor.execute("INSERT INTO users (name, email) VALUES ('Jane', 'jane@example.com')")  # HIGH severity
cursor.execute("DROP TABLE users")  # CRITICAL severity
cursor.execute("TRUNCATE TABLE users")  # CRITICAL severity

# 2. SQL mutations with variables
user_id = 1
new_name = "Updated Name"
cursor.execute(f"DELETE FROM users WHERE id = {user_id}")
cursor.execute(f"UPDATE users SET name = '{new_name}' WHERE id = {user_id}")
cursor.execute(f"INSERT INTO users (name) VALUES ('{new_name}')")

# 3. SQL mutations with format strings
query_delete = "DELETE FROM products WHERE price < {}"
query_update = "UPDATE products SET price = price * {} WHERE category = '{}'"
cursor.execute(query_delete.format(10))
cursor.execute(query_update.format(1.1, 'electronics'))

# 4. SQL mutations with .format() method
delete_query = "DELETE FROM orders WHERE date < '{}'"
update_query = "UPDATE orders SET status = '{}' WHERE id = {}"
cursor.execute(delete_query.format('2023-01-01'))
cursor.execute(update_query.format('cancelled', 123))

# 5. SQL mutations with % formatting
cursor.execute("DELETE FROM logs WHERE timestamp < '%s'" % '2023-01-01')
cursor.execute("UPDATE settings SET value = '%s' WHERE key = '%s'" % ('new_value', 'config_key'))

# 6. Chain SQL operations
def cleanup_database():
    cursor.execute("DELETE FROM temp_data WHERE created_at < '2023-01-01'")
    cursor.execute("UPDATE users SET last_login = NULL WHERE active = 0")
    cursor.execute("INSERT INTO audit_log (action, timestamp) VALUES ('cleanup', datetime('now'))")

# 7. SQL in loops
user_ids = [1, 2, 3, 4, 5]
for uid in user_ids:
    cursor.execute(f"DELETE FROM user_sessions WHERE user_id = {uid}")
    cursor.execute(f"UPDATE users SET login_count = 0 WHERE id = {uid}")

# 8. Conditional SQL mutations
if True:  # Some condition
    cursor.execute("DELETE FROM expired_tokens WHERE expires_at < datetime('now')")
    cursor.execute("UPDATE users SET status = 'inactive' WHERE last_login < '2022-01-01'")

# 9. SQL mutations in functions
def delete_old_records(table_name, days_old):
    query = f"DELETE FROM {table_name} WHERE created_at < date('now', '-{days_old} days')"
    cursor.execute(query)

def update_user_status(user_id, status):
    cursor.execute(f"UPDATE users SET status = '{status}' WHERE id = {user_id}")

def batch_insert_users(users_data):
    for user in users_data:
        cursor.execute(f"INSERT INTO users (name, email) VALUES ('{user['name']}', '{user['email']}')")

# 10. Class-based SQL mutations
class DatabaseManager:
    def __init__(self, connection):
        self.conn = connection
        self.cursor = connection.cursor()
    
    def cleanup_old_data(self):
        self.cursor.execute("DELETE FROM logs WHERE timestamp < date('now', '-30 days')")
        self.cursor.execute("DELETE FROM temp_files WHERE created_at < date('now', '-7 days')")
    
    def update_user_preferences(self, user_id, preferences):
        self.cursor.execute(f"UPDATE user_preferences SET data = '{preferences}' WHERE user_id = {user_id}")
    
    def archive_old_orders(self):
        self.cursor.execute("INSERT INTO archived_orders SELECT * FROM orders WHERE created_at < '2022-01-01'")
        self.cursor.execute("DELETE FROM orders WHERE created_at < '2022-01-01'")

# 11. SQL with pandas (common pattern)
def pandas_sql_operations():
    # SQL queries that would be detected
    df = pd.read_sql("SELECT * FROM users WHERE active = 1", conn)
    
    # These should be detected as mutations
    pd.read_sql("DELETE FROM temp_table WHERE processed = 1", conn)
    pd.read_sql("UPDATE statistics SET last_updated = datetime('now')", conn)
    pd.read_sql("INSERT INTO processed_data SELECT * FROM raw_data", conn)

# 12. Multi-line SQL queries
multiline_delete = """
DELETE FROM users 
WHERE last_login < '2022-01-01' 
AND status = 'inactive'
"""
cursor.execute(multiline_delete)

multiline_update = """
UPDATE products 
SET price = price * 1.1,
    updated_at = datetime('now')
WHERE category IN ('electronics', 'books')
"""
cursor.execute(multiline_update)

# 13. SQL with JOIN operations (still mutations)
complex_delete = """
DELETE u FROM users u
JOIN user_sessions s ON u.id = s.user_id
WHERE s.last_activity < '2022-01-01'
"""
cursor.execute(complex_delete)

complex_update = """
UPDATE orders o
JOIN customers c ON o.customer_id = c.id
SET o.status = 'cancelled'
WHERE c.account_status = 'suspended'
"""
cursor.execute(complex_update)

# 14. SQL mutations with transactions
def transactional_operations():
    cursor.execute("BEGIN TRANSACTION")
    try:
        cursor.execute("DELETE FROM order_items WHERE order_id = 123")
        cursor.execute("UPDATE orders SET total = 0 WHERE id = 123")
        cursor.execute("INSERT INTO refunds (order_id, amount) VALUES (123, 100.00)")
        cursor.execute("COMMIT")
    except:
        cursor.execute("ROLLBACK")

# 15. SQL with prepared statements (still detectable)
def prepared_statements():
    # Even with parameterized queries, these are still mutations
    cursor.execute("DELETE FROM users WHERE id = ?", (1,))
    cursor.execute("UPDATE users SET name = ? WHERE id = ?", ("New Name", 1))
    cursor.execute("INSERT INTO users (name, email) VALUES (?, ?)", ("John", "john@example.com"))

# 16. SQL mutations with error handling
def safe_sql_operations():
    try:
        cursor.execute("DELETE FROM invalid_records WHERE validation_failed = 1")
        cursor.execute("UPDATE processed_records SET status = 'completed'")
    except Exception as e:
        print(f"Error: {e}")
        cursor.execute("INSERT INTO error_log (message, timestamp) VALUES (?, datetime('now'))", (str(e),))

# 17. Dynamic SQL generation
def generate_cleanup_queries(tables):
    for table in tables:
        delete_query = f"DELETE FROM {table} WHERE archived = 1"
        update_query = f"UPDATE {table} SET archived = 1 WHERE created_at < '2022-01-01'"
        cursor.execute(delete_query)
        cursor.execute(update_query)

# 18. SQL with string concatenation
base_query = "DELETE FROM "
table_name = "old_records"
condition = " WHERE created_at < '2022-01-01'"
full_query = base_query + table_name + condition
cursor.execute(full_query)

# 19. SQL mutations in list comprehensions (edge case)
tables_to_clean = ['logs', 'temp_data', 'cache']
queries = [f"DELETE FROM {table} WHERE expired = 1" for table in tables_to_clean]
for query in queries:
    cursor.execute(query)

# 20. Nested SQL operations
def complex_data_migration():
    # First, backup data
    cursor.execute("INSERT INTO backup_users SELECT * FROM users WHERE active = 0")
    
    # Then update and delete
    cursor.execute("UPDATE users SET migrated = 1 WHERE active = 0")
    cursor.execute("DELETE FROM users WHERE active = 0 AND migrated = 1")
    
    # Finally, cleanup
    cursor.execute("DELETE FROM backup_users WHERE created_at < date('now', '-1 year')")

# 21. SQL with regex patterns (advanced edge case)
def pattern_based_cleanup():
    # These should still be detected even with complex patterns
    cursor.execute("DELETE FROM logs WHERE message REGEXP '^ERROR.*timeout.*'")
    cursor.execute("UPDATE users SET email = LOWER(email) WHERE email REGEXP '.*[A-Z].*'")

# 22. Batch operations
def batch_sql_operations():
    operations = [
        "DELETE FROM expired_sessions WHERE expires_at < datetime('now')",
        "UPDATE users SET last_cleanup = datetime('now')",
        "INSERT INTO maintenance_log (action, timestamp) VALUES ('cleanup', datetime('now'))"
    ]
    
    for operation in operations:
        cursor.execute(operation)

# Close connection
conn.close() 