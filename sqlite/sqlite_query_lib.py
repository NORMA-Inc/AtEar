# coding: utf-8

import sqlite3
import hashlib
import json

class sqlite_query_lib:

	sqlite3_dbname = ""
	db = None
	cursor = None

	def open(self, sqlite3_name):

		self.sqlite3_dbname = sqlite3_name
		self.db = sqlite3.connect(self.sqlite3_dbname)
		self.cursor = self.db.cursor()

		self.cursor.execute('PRAGMA foreign_keys=ON')

	def close(self):
		if self.db != None:
			self.db.close()

	def commit(self):
		self.db.commit()

	def sql_exec(self,sql):
		self.cursor.execute(sql)
		self.commit()

		return self.cursor

	def sql_exec_param(self,sql,data):
		self.cursor.execute(sql,data)
		self.commit()

		return self.cursor

	def sql_exec_param_many(self,sql,datas):
		self.cursor.executemany(sql,datas)
		self.commit()

		return self.cursor

	def sqlite_create_table(self,table_name,columns):
		self.sql_exec(self.genCreateTableSql(table_name, columns))

	def genCreateTableSql(self,table_name,columns):
		create_table_sql = "create table " + table_name + "("

		for col in columns:
			create_table_sql += col+","

		create_table_sql = create_table_sql.rstrip(",") + ")"

		return create_table_sql

	def sqlite_drop_table(self, table_name):
		self.sql_exec(self.genDropTableSql(table_name));
 
 
	def genDropTableSql(self, table_name):
		drop_table_sql = "drop table " + table_name;
		return drop_table_sql;

	def genHashedPassword(self,password):
		hashed_password = hashlib.sha512(password).hexdigest()

		return hashed_password

	def insert_user(self,username,password):
		insert_user_sql = "insert into users (username,password) values(?,?)"
		hash_password = self.genHashedPassword(password)
		data = [username,hash_password]
		return self.sql_exec_param(insert_user_sql,data)

	def select_user(self,username,password):
		select_user_sql = "select password from users where username = ?"
		data = [username]
		cursor = self.sql_exec_param(select_user_sql,data)
		
		db_password = cursor.fetchone()
		input_password = self.genHashedPassword(password)
		
		if db_password is None:
			return 0
		elif db_password[0] == input_password:
			return 1
		else:
			return -1

	def insert_project(self,username,p_name,p_desc,p_time):
		insert_project_sql = "insert into projects (p_name,p_desc,p_time,username) values(?,?,?,?)"
		data = [p_name,p_desc,p_time,username]
		cursor = self.sql_exec_param(insert_project_sql,data)
		p_idx = cursor.lastrowid

		json_result = { 'id' : p_idx }

		return json.dumps(json_result)

	def select_project(self,username,idx=None):
		if idx:
			select_project_sql = "select * from projects where username=? and p_id=?"
			data = [username,idx]
		else:
			select_project_sql = "select * from projects where username=?"
			data = [username]

		cursor = self.sql_exec_param(select_project_sql,data)
		result = cursor.fetchall()
		json_result = []
		for row in result:
			d = {'id' : row[0],
				'p_name' : row[1],
				'p_desc' : row[2],
				'p_time' : row[3]
				}
			json_result.append(d)
		return json.dumps(json_result)

	def update_project(self,idx,p_name,p_desc,p_time):
		update_project_sql = "update projects set p_name=?,p_desc=?,p_time=? where idx=?"
		data = [p_name,p_desc,p_time,idx]
		cursor = self.sql_exec_param(update_project_sql,data)
		p_idx = cursor.lastrowid

		json_result = { 'id' : p_idx }

		return json.dumps(json_result)

	def delete_project(self,idx):
		delete_project_sql = "delect from projects where idx=?"
		data = [idx]

		return self.sql_exec_param(delete_project_sql,data)

	def insert_cell(self,cellname,p_id):
		insert_cell_sql = "insert into cells (cellname,p_id) values(?,?)"
		data = [cellname,p_id]
		cursor = self.sql_exec_param(insert_cell_sql,data)
		c_id = cursor.lastrowid

		return c_id

	def insert_scan_data(self,datas):
		insert_scan_data_sql = "insert or replace into scandata values(?,?,?,?,?,?,?,?,?,?,?,?,?)"
		cursor = self.sql_exec_param_many(insert_scan_data_sql,datas)

		return cursor