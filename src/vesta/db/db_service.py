from os.path import abspath, dirname

import psycopg
from psycopg.rows import dict_row
from psycopg import sql


class DB:
    def __init__(self, user, password, host, port, db):
        try:
            self.conn = psycopg.connect(
                user=user,
                password=password,
                host=host,
                port=port,
                dbname=db,
                row_factory=dict_row
            )
        except psycopg.Error as e:
            print(f"Error connecting to PostGreSQL : {e}")
            exit()

        self.cur = self.conn.cursor()

    def getUserCredentials(self, email):
        self.cur.execute('SELECT id,password,verified FROM account WHERE email = %s', (email,))
        r = self.cur.fetchone()
        if r:
            r["password"] = bytes(r["password"])
            return r
        else:
            return

    def getUser(self, id, target='*'):
        self.cur.execute(sql.SQL('SELECT email FROM account WHERE id = %s'), (id,))
        r = self.cur.fetchone()
        if r:
            return r
        else:
            return

    def createAccount(self, email, password, parrain):
        if parrain:
            self.cur.execute(
                "insert into account (email,password,inscription,verified,parrain) values(%s,%s,CURRENT_DATE,FALSE,%s) "
                "RETURNING id", (email, password, parrain))
        else:
            self.cur.execute(
                "insert into account (email,password,inscription,verified) values(%s,%s,CURRENT_DATE,FALSE) "
                "RETURNING id", (email, password))
        r = self.cur.fetchone()
        self.conn.commit()
        return r['id']

    def getSomething(self, table, id, selector='id'):
        try:
            self.cur.execute(
                sql.SQL('SELECT * FROM {} WHERE {} = %s').format(sql.Identifier(table), sql.Identifier(selector)), (id,))
            r = self.cur.fetchone()
            if r:
                return r
            else:
                return []
        except Exception as e:
            print(f"[VESTA] An error occurred with the db: {e}")
            self.conn.rollback()

    def getAll(self, table, id, selector='id'):
        try:
            self.cur.execute(
                sql.SQL('SELECT * FROM {} WHERE {} = %s').format(sql.Identifier(table), sql.Identifier(selector)), (id,))
            r = self.cur.fetchall()
            if r:
                return r
            else:
                return []
        except Exception as e:
            print(f"[VESTA] An error occurred with the db: {e}")
            self.conn.rollback()

    def getSomethingProxied(self, table, proxy, commonTable, id):
        '''
        Get something described by a ManyToMany relation
        example :
        a company --> you want to get all the company of a user
        table is the element you want (company)
        proxy is the table that make the relation (accessCompany)
        commonTable is the one that link the two (account)
        id is the id you want to query (user id)

        this assumes that your proxy table has a key named like table and commonTable
        eg :
        accessCompany :
            id
            company
            account
        '''

        table = sql.Identifier(table)
        proxy = sql.Identifier(proxy)
        commonTable = sql.Identifier(commonTable)
        try:
            self.cur.execute(
                sql.SQL('SELECT {}.* FROM {},{} WHERE {}.{}=%s and {}.id={}.{}').format(table, table, proxy,
                                                                                        proxy, commonTable, table,
                                                                                        proxy, table), (id,))
            r = self.cur.fetchall()
            if r:
                return r
            else:
                return []
        except Exception as e:
            print(f"[VESTA] An error occurred with the db: {e}")
            self.conn.rollback()


    def getFilters(self, table, filter, basis = None):
        # this take a filter in the following format
        # [identifier, operation, value, AND/OR... if relevant, ...]

        if basis:
            condition = [sql.SQL(basis)]
        else:
            condition = []
        values = []
        for i in range(0, len(filter), 4):
            if filter[i+1].upper() == 'IN':
                values += filter[i+2]
                placeholders = ','.join(['%s'] * len(filter[i+2]))
                placeholders = " (" + placeholders + ")"
            elif filter[i+2] == None:
                placeholders = " NULL"
            elif filter[i+2] == "true":
                placeholders = " true"
            elif filter[i+2] == "false":
                placeholders = " false"
            else:
                values.append(filter[i+2])
                placeholders = " %s"
            if i+4 <= len(filter):
                condition.append(sql.Identifier(filter[i]))
                condition.append(sql.SQL(filter[i+1]+placeholders+" "+filter[i+3]))
            else:
                condition.append(sql.Identifier(filter[i]))
                condition.append(sql.SQL(filter[i+1]+placeholders))
        try:
            query = sql.SQL('SELECT * FROM {} WHERE {condition}').format(sql.Identifier(table), condition=sql.SQL(' ').join(condition))
            self.cur.execute(query, values)
            r = self.cur.fetchall()
            if r:
                return r
            else:
                return []
        except Exception as e:
            print(f"[VESTA] An error occurred with the db: {e}")
            self.conn.rollback()

    def insertDict(self, table, dict, getId=False):
        cols = []
        vals = []
        for key in dict:
            cols.append(sql.Identifier(key))
            vals.append(dict[key])
        cols_str = sql.SQL(',').join(cols)
        vals_str = sql.SQL(','.join(['%s' for i in range(len(vals))]))
        if getId:
            sql_str = sql.SQL("INSERT INTO {} ({}) VALUES ({}) ON CONFLICT DO NOTHING RETURNING id ").format(sql.Identifier(table), cols_str,
                                                                                                             vals_str)
        else:
            sql_str = sql.SQL("INSERT INTO {} ({}) VALUES ({}) ON CONFLICT DO NOTHING").format(sql.Identifier(table), cols_str, vals_str)
        self.cur.execute(sql_str, vals)
        self.conn.commit()
        if getId:
            r = self.cur.fetchone()
            self.conn.commit()
            return r['id']

    def insertReplaceDict(self, table, dict):
        cols = []
        vals = []
        for key in dict:
            cols.append(sql.Identifier(key))
            vals.append(dict[key])
        cols_str = sql.SQL(',').join(cols)
        vals_str = sql.SQL(','.join(['%s' for i in range(len(vals))]))
        sql_str = sql.SQL("INSERT INTO {} ({}) VALUES ({}) ON CONFLICT (id) DO UPDATE SET ({}) = ({})"
                          ).format(sql.Identifier(table), cols_str, vals_str, cols_str,
                                   vals_str)  # warning only working for dicts containing an id
        self.cur.execute(sql_str, vals * 2)
        self.conn.commit()

    def init(self):
        self.cur.execute(open("./db/create_db.sql", "r").read())
        self.conn.commit()

    def resetTable(self, table):
        sql_str = """delete from {} cascade;ALTER SEQUENCE {} RESTART WITH 1""".format(table, table + "_id_seq")
        self.cur.execute(sql_str)
        self.conn.commit()

    def edit(self, table, id, element, value, selector='id'):
        self.cur.execute(
            sql.SQL("UPDATE {} SET {} = %s WHERE {} = %s ").format(sql.Identifier(table), sql.Identifier(element), sql.Identifier(selector)),
            (value, id))
        self.conn.commit()

    def deleteSomething(self, table, id, selector='id'):
        sql_str = sql.SQL('DELETE FROM {} WHERE {} = %s').format(sql.Identifier(table), sql.Identifier(selector))
        self.cur.execute(sql_str, (id,))
        self.conn.commit()

    def initUniauth(self):
        self.cur.execute(open(dirname(abspath(__file__)) + "/UNIAUTH.sql", "r").read())
        self.conn.commit()

    def postUniBridgeData(self, source, name, value=None, related=None):
        data = {"source": source, "name": name}
        if value:
            data["value"] = value
        if related:
            data["related_table"] = related

        self.insertDict("unibridge", data)

    #notif name should NEVER be arbitrary
    def postUniBridgeNotification(self, notif_name, element):
        if self.getSomething("unibridge", notif_name, "related_table"):
            self.insertDict(notif_name, element)
        else:
            raise Exception(f"Notification {notif_name} does not exist in unibridge table")

    def createTable(self, name, schema):
        """
        Create a new table in the database with the given name and schema.
        :param name: Name of the table to create.
        :param schema: SQL schema definition for the table.
        """
        try:
            self.cur.execute(sql.SQL("CREATE TABLE IF NOT EXISTS {} ({})").format(sql.Identifier(name), sql.SQL(schema)))
            self.conn.commit()
        except psycopg.Error as e:
            print(f"Error creating table {name}: {e}")
            self.conn.rollback()

    def getUnibridgeNotifs(self, notif_name, selector='id', selector_value=None):
        if self.getSomething("unibridge", notif_name, "related_table"):
            if selector_value:
                return self.getAll("unibridge", selector_value, selector)

            self.cur.execute(sql.SQL("SELECT * FROM {}").format(sql.Identifier(notif_name)))
            return self.cur.fetchall()
        else:
            raise Exception(f"Notification {notif_name} does not exist in unibridge table")