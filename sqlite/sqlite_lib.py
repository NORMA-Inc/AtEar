# coding: utf-8
 
import sqlite3
import hashlib
 
class sqlite_lib:
 
	sqlite3_dbname = ""
	db = None
	cursor = None
 
	def open(self, sqlite3_name):
 
		self.sqlite3_dbname = sqlite3_name
		self.db = sqlite3.connect(self.sqlite3_dbname)
		self.cursor = self.db.cursor()
 
 
	def close(self):
		if self.db != None:
			self.db.close()
 
 
	def commit(self):
		self.db.commit()
 
 
	def sql_exec(self, sql):
		self.cursor.execute(sql)
		self.commit()
 
		return self.cursor
 
 
	def sqlite_create_table(self, table_name, columns):
		self.sql_exec(self.genCreateTableSql(table_name, columns))
 
 
	def genCreateTableSql(self, table_name, columns):
		create_table_sql = "create table " + table_name +"(";
 
		for col in columns:
			create_table_sql+= col+","
 
		create_table_sql = create_table_sql.rstrip(",") + ")"
 
		return create_table_sql;
		
 
	def sqlite_drop_table(self, table_name):
		self.sql_exec(self.genDropTableSql(table_name));
 
 
	def genDropTableSql(self, table_name):
		drop_table_sql = "drop table " + table_name;
		return drop_table_sql;
 
	def sqlite_insert_data(self, table_name, columns, values):
		return self.sql_exec(self.genInsertIntoValueSql(table_name, columns,values))
 
 
	def genInsertIntoValueSql(self, table_name, columns, values):
		insert_into_value_sql = "insert into "+table_name+"("
 		for column in columns:
 			insert_into_value_sql+= column+","

 		insert_into_value_sql = insert_into_value_sql.rstrip(",") + ") values("
		
		for val in values:
			insert_into_value_sql+= val+","
 
		insert_into_value_sql = insert_into_value_sql.rstrip(",") + ")"
 
		return insert_into_value_sql;
 
 
	def sqlite_delete_data(self, table_name, where):
		self.sql_exec(self.genDeleteFromWhereSql(table_name, where))
 
 
	def genDeleteFromWhereSql(self, table_name, where):
		return  "delete from " + table_name +" where " + where
 
 
	def sqlite_update_data(self, table_name, columns_values_dict_list, where):
		print self.genUpdateSetWhereSql(table_name, 
											  columns_values_dict_list, where)
		return self.sql_exec(self.genUpdateSetWhereSql(table_name, 
											  columns_values_dict_list, where))
 
 
 
	def genUpdateSetWhereSql(self, table_name, columns_values_dict_list, where):
		update_set_where_sql = "update "+table_name+" set "
		for columns_values_dict in columns_values_dict_list:
 
			update_set_where_sql += columns_values_dict.keys()[0]+"="+columns_values_dict.values()[0]+","
 
		return update_set_where_sql.rstrip(",")+" where "+ where
 
 
	def sqlite_select_data(self, table_name, columns, where=None):
		return self.sql_exec(self.genSelectFromWhereSql(table_name, columns, where))

	def genSelectFromWhereSql(self, table_name, columns, where=None):
		select_from_where_sql = "select ";
 
		for column in columns:
			select_from_where_sql += column+","

 		if where:
			return select_from_where_sql.rstrip(",")+" from "+table_name+" where "+ where
		else:
			return select_from_where_sql.rstrip(",")+" from "+table_name

	def genHashed(self,password):
		hashed_password = hashlib.sha512(password).hexdigest()

		return hashed_password