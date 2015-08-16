# coding: utf-8
__author__ = 'NORMA_ATEAR'
from sqlite_query_lib import sqlite_query_lib

def create_database(DATABASE):
	db = sqlite_query_lib()
	db.open(DATABASE)

	db.sqlite_drop_table("if exists users")
	db.sqlite_drop_table("if exists projects")
	db.sqlite_drop_table("if exists user_project")

	"""Create users table"""
	db.sqlite_create_table("users",[\
		"username text primary key",\
		"password text not null"\
		])

	"""Create project table"""
	db.sqlite_create_table("projects",[\
		"idx integer primary key autoincrement",\
		"p_name text not null",\
		"p_desc text",\
		"p_time text",\
		"username text not null",\
		"FOREIGN KEY (username) references users(username) ON DELETE CASCADE"\
		])

	db.sqlite_create_table("cells",[\
		"idx integer primary key autoincrement",\
		"cellname text",\
		"p_id integer",\
		"FOREIGN KEY (p_id) references projects(idx) ON DELETE CASCADE"\
		])

	db.sqlite_create_table("scandata",[\
		"bssid text primary key",\
		"type text",\
		"company text",\
		"essid text",\
		"ch integer",\
		"enc text",\
		"nb_data text",\
		"nb_beacons text",\
		"power integer",\
		"product text",\
		"clients text",\
		"sid_length integer",\
		"c_id integer not null",\
		"FOREIGN KEY (c_id) references cells(idx) ON DELETE CASCADE"\
		])


	"""Set default admin"""
	db.insert_user('admin','admin')
	db.insert_user('conf','conf')

	db.close()

if __name__ == '__main__':
	create_database()
