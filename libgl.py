import requests
from requests.auth import HTTPBasicAuth
import urllib.parse as urlparse
from urllib.parse import parse_qs
import webbrowser
import json



from datetime import datetime, timedelta

cookies = {
}

headers = {
    'Connection': 'keep-alive',
    'Cache-Control': 'max-age=0',
    'Authorization': 'Basic ',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.90 Safari/537.36',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-User': '?1',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3',
    'Sec-Fetch-Site': 'none',
    'Accept-Encoding': 'gzip, deflate, br',
    'Accept-Language': 'en-US,en;q=0.9,ru;q=0.8',
}

headers_map = {
    'Accept': 'application/json, text/plain, */*',
    'Referer': 'https://portal.globallogic.com',
    'Origin': 'https://portal.globallogic.com',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.90 Safari/537.36',
  	'Authorization': 'Bearer ',
	'Sec-Fetch-Mode': 'cors',
}

headers_erp = {
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Site': 'same-origin',
    'Origin': 'https://erp.globallogic.com',
    'Accept-Encoding': 'gzip, deflate, br',
    'Accept-Language': 'en-US,en;q=0.9,ru;q=0.8',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.90 Safari/537.36',
    'Content-type': 'application/x-www-form-urlencoded',
    'Accept': '*/*',
    'Referer': 'https://erp.globallogic.com/OA_HTML/AppsLocalLogin.jsp?langCode=US&_logoutRedirect=y',
    'X-Service': 'AuthenticateUser',
}

place_info = ()
loc_info = ()
emp_info = ()
locations_all = ()
emp_all = ()
settings = ()

def fillAuth(settings):
	headers_map['Authorization'] = 'Bearer ' + settings['bearer']['bearer']
	headers['Authorization'] = settings['basic']

def authBasic(url, username, password):
	session = requests.Session()
	session.auth = HTTPBasicAuth(username, password)
	request = requests.Request('GET', url)
	res = (session.prepare_request(request)).headers["Authorization"]	
	response = session.get(url)
	if response.status_code == 200:
		return res
	
	print("Auth error on: " + url +'\n'+str(response.content))
		
	return None


def authBearer(username, password):
	payload = json.loads('{"client_id":"v3.1a397079-5a5c-450b-8c71-519b50b5eb73","state":"Zwdsr2m2121","redirect_uri":"https://portal.globallogic.com/auth/callback","scope":"","response_type":"code","login":"login","password":"password"}')
	payload["login"] = username
	payload["password"] = password
	response = requests.post("https://accounts.globallogic.com/api/oauth/v2.0/authorize/", json=payload)
	if response.status_code == 200:
		lcookies = response.cookies
		headers=headers_map
		req_content = json.loads(response.content)
		headers['Referer'] = req_content['redirect_uri']
		headers['Access-Control-Request-Headers'] = 'content-type'
		headers['Access-Control-Request-Method'] = 'POST'
		parsed = urlparse.urlparse(req_content['redirect_uri'])
		code = urlparse.parse_qs(parsed.query)['code']
		response = requests.options('https://accounts.globallogic.com/api/oauth/v3/token', cookies = lcookies, headers=headers )
		payload = json.loads('{"grant_type":"authorization_code","redirect_uri":"https://portal.globallogic.com/auth/callback","client_id":"1a397079-5a5c-450b-8c71-519b50b5eb73","client_secret":"FNT8ppyBLriZdUT5PIFAamcjAHIba6o025gQ-KVABb0pn7rJ53tp5g","code":"'+str(code[0])+'"}')
		response = requests.post("https://accounts.globallogic.com/api/oauth/v3/token", json=payload)
		if response.status_code == 200:
			res = dict()
			resp_json = response.json()
			res["bearer"] = resp_json["access_token"]
			res["refresh"] = resp_json["refresh_token"]
			res["expired_time"] = resp_json["expired_time"]
			return res
		else:
			print("Get bearer error(2):")
			print(response.content)


	else:
		print("Get bearer error(1):")
		print(response.content)
			
		
		
def authErp(username, password):
	data = {
	  'username': username,
	  'password': password,
	  '_lAccessibility': 'N',
	  'displayLangCode': 'US',
	  'langCode': 'US'
	}
	
	session = requests.Session()
	
	response = session.post('https://erp.globallogic.com/OA_HTML/AppsLocalLogin.jsp', headers=headers_erp, data=data, verify=False)
	if response.status_code == 200:
		return dict(session.cookies)
		
	else:
		print("ERP auth error:"+response.content)

	
def whereEmp(zone, uid):
	params = (
		('zone', zone),
		('employeeId', uid),
	)
	
	response = requests.get('https://portal-ua.globallogic.com/officetime/json/last_seen.php', headers=headers, params=params)
	return json.loads(response.content)
	
def findEmp(employees, first_name, second_name):
	results = []
	for emp in employees:
		if (emp["first_name"] == first_name) & (emp["last_name"] == second_name):
			results.append(emp);
	
	return results
	
def findEmpByParam(employees, arg, param_name):
	results = []
	for emp in employees:
		if (emp[param_name] == arg):
			results.append(emp);
	
	return results
	
def findEmpN(employees, first_name, second_name):
	results = []
	results.append(findEmp(employees, first_name,  second_name))
	results.append(findEmp(employees, second_name, first_name))
	
	return results
	

	
def needCacheRowUpdate(elem, dict):
	perform = False
	if str(elem) not in dict:
		perform=True
	#	print("Not found in cache")
	else:
		border = datetime.now() - timedelta(weeks=1)
		try:
			if  (border >= datetime.strptime(dict[str(elem)]["cache_timestamp"], '%Y/%m/%d %H:%M:%S')):
				#print (border.strftime('%Y/%m/%d %H:%M:%S'))
				perform=True
				
		except:
			perform=True
			
	return perform

def performCacheRowUpdate(req, headers_send):
	response = requests.get(req, headers = headers_send)
	if response.status_code != 200:
		print("performCacheRowUpdate Err:")
		print(response.status_code)
		print(response.content)
		return None
	el = json.loads(response.content)
	el["cache_timestamp"] = datetime.now().strftime('%Y/%m/%d %H:%M:%S')
	return el
	
	
def needCacheRowUpdateSingleRow(dict, weeks_count):
	perform = False
	border = datetime.now() - timedelta(weeks=weeks_count)
	try:
		if  (border >= datetime.strptime(dict["cache_timestamp"], '%Y/%m/%d %H:%M:%S')):
			perform = True
	except:
		perform = True	
		
	return perform
	
def performCacheRowUpdateSingleRow(req, headers_send, cookies_send=None):
	response = requests.get(req, headers = headers_send, cookies = cookies_send)
	if response.status_code != 200:
		print("performCacheRowUpdate Err:")
		print(response.status_code)
		print(response.content)
		return None
		
	el=dict()
	el["data"] = json.loads(response.content)
	el["cache_timestamp"] = datetime.now().strftime('%Y/%m/%d %H:%M:%S')
	return el


	
def getALLEmp():
	global emp_all
	print("getALLEmp")
	if (needCacheRowUpdateSingleRow(emp_all, 1) == True):
		emp_all = performCacheRowUpdateSingleRow('https://portal-ua.globallogic.com/officetime/json/employees.php', headers, cookies)

	return emp_all["data"]
	
	
def getAllLocations(headers_map):
	global locations_all
	print("getAllLocations")
	if (needCacheRowUpdateSingleRow(locations_all, 8) == True):
		locations_all = performCacheRowUpdateSingleRow('https://portal-apps.globallogic.com/officemap/api/v1/locations', headers_map)
			
	return locations_all["data"]
		
def printLocation(locations):
	results=[]
	for country in locations["countries"]:
		print('\t'+country["name"])
		for city in country["cities"]:
			print('\t\t'+city["name"])
			for loc in city["locations"]:
				print('\t\t\t'+loc["name"])

	
def searchLocation(locations, zone_name):
	print("searchLocation in "+zone_name)
	results=[]
	for country in locations["countries"]:
		for city in country["cities"]:
			for loc in city["locations"]:
				if loc["name"].find(zone_name) != -1:
					result=dict()
					result["country"] = country["name"]
					result["city"] = city["name"]
					result["loc"] = loc
					results.append(result)
	
	return results
	
def getLocInfo(loc_id):
	global loc_info
	if needCacheRowUpdate(loc_id, loc_info) == True:
		loc_info[str(loc_id)] = performCacheRowUpdate('https://portal-apps.globallogic.com/officemap/api/v1/block/'+str(loc_id), headers_map)
	return loc_info[str(loc_id)] 

def getEmpInfo(user_name):
	global emp_info
	if needCacheRowUpdate(user_name, emp_info) == True:
		emp_info[str(user_name)] = performCacheRowUpdate('https://portal-apps.globallogic.com/profile/api/v1/employee/'+str(user_name)+'/detail', headers_map)
		
	return emp_info[str(user_name)] 
	
def getPlaceInfo(id):
	global place_info
	if needCacheRowUpdate(id, place_info) == True:
		place_info[str(id)] = performCacheRowUpdate('https://portal-apps.globallogic.com/officemap/api/v1/place/'+str(id), headers_map)
	
	return place_info[str(id)]
	

def searchSeat(locs, first_name, last_name):
	seats=[]
	print("searchSeat " + str(first_name) + str(last_name))
	try:
		full_name =  first_name+" "+last_name
	except:
		return seats
	for loc in locs:
		for block in loc["loc"]["blocks"]:
			blockInfo = getLocInfo(block["id"])
			for val in blockInfo['data']:
				obj = blockInfo['data'][val]
				try:
					if obj['name'].find(full_name) != -1:
						res=dict()
						res["office_location"] = loc["loc"]["google_url"]
						res["loc_info_ext"] = getPlaceInfo(val)["data"]
						res["emp_info"] = obj
						res["ext_info"] = getEmpInfo(obj["username"])
						res["glo_url"] = "https://glo.globallogic.com/users/profile/"+obj["username"]+"#"
						loc_data = res["loc_info_ext"]
						res["emp_office_url"] = "https://portal.globallogic.com/glm/view/block/" + loc["country"] +"/" \
							+ loc["city"] + "/" +loc_data["city_uniq_id"] + "/" \
							+ loc_data["location_name"] + "/" +loc_data["location_uniq_id"] + "/" \
							+ loc_data["block_name"] + "/" + str(loc_data["block_id"]) \
							+ "/tableid/" + str(loc_data["id"])
						
						seats.append(res)
							
				except Exception as ex:
					pass
					
	return seats
	
def searchSeatUsername(locs, username):
	seats=[]
	for loc in locs:
		for block in loc["loc"]["blocks"]:
			blockInfo = getLocInfo(block["id"])
			for val in blockInfo['data']:
				obj = blockInfo['data'][val]
				try:
					if obj['username'].find(username) != -1:
						res=dict()
						res["office_location"] = loc["loc"]["google_url"]
						res["loc_info_ext"] = getPlaceInfo(val)["data"]
						res["emp_info"] = obj
						res["ext_info"] = getEmpInfo(obj["username"])
						res["glo_url"] = "https://glo.globallogic.com/users/profile/"+obj["username"]+"#"
						loc_data = res["loc_info_ext"]
						res["emp_office_url"] = "https://portal.globallogic.com/glm/view/block/" + loc["country"] +"/" \
							+ loc["city"] + "/" +loc_data["city_uniq_id"] + "/" \
							+ loc_data["location_name"] + "/" +loc_data["location_uniq_id"] + "/" \
							+ loc_data["block_name"] + "/" + str(loc_data["block_id"]) \
							+ "/tableid/" + str(loc_data["id"])
						
						seats.append(res)
							
				except Exception as ex:
					pass
					
	return seats
	
def findEmpS(employees, single_param):
	results = []
	results.append(findEmpByParam(employees, single_param,  "last_name"))
	try:
		uid = int(single_param)
		results.append(findEmpByParam(employees, uid,  "uid"))
	except ValueError as verr:
	  pass # do job to handle: s does not contain anything convertible to int
	except Exception as ex:
	  pass # do job to handle: Exception occurred while converting to int

	return results


def findAlive(employees):
	results = []
	count=0
	alive_count=0
	total_count=len(employees)
	locations = getAllLocations(headers_map)
	border = datetime.now() - timedelta(weeks=5)
	for emp in employees:
		loc=whereEmp(emp["zone"], emp["uid"])
		count +=1
		try:
			emp_now = datetime.strptime(loc["timestamp"], '%Y/%m/%d %H:%M:%S')
			if emp_now > border:
				alive_count += 1
				loc = searchLocation(locations, emp["zone"])
				seats = searchSeat(loc, emp["first_name"], emp["last_name"])
				results.append(emp)

		except Exception as ex:
			print(emp)
			print(loc)

		print(":"+str(count)+"/"+str(total_count)+" Alive found: "+str(alive_count))

	return results
	
def getEmpWorkingHoursRaw(zone, uid, timestamp_from, timestamp_till):
	params = (
		('zone', zone),
		('employeeId', uid),
		('from', timestamp_from),
		('till', timestamp_till)
	)
	
	response = requests.get('https://portal-ua.globallogic.com/officetime/legacy/index_new.php', headers=headers, params=params, cookies=cookies)
	if (response.status_code != 200):
		return None
		
	return str(response.content)
	
def getEmpWorkingHours(zone, uid, timestamp_from, timestamp_till):
	searchStr = "Total for the period: "
	cont = getEmpWorkingHoursRaw(zone, uid, timestamp_from, timestamp_till)
	
	pos = str(cont).find(searchStr)
	if pos != -1:
		res = str(cont)[(pos + len(searchStr)):]
		res = res[:res.find("</div>")]
		return res
		
def summaryResults(results, open, detect_loc, working_hours_period):
	json=[]
	timestamp_days = int(working_hours_period[0])
	locations = getAllLocations(headers_map)

	
	timestamp_from = 0
	if  timestamp_days > 0:
		timestamp_from = (datetime.now() - timedelta(days=timestamp_days)).timestamp() * 1000
		
	
	for emp_arr in results:
		if (len(emp_arr) > 0):
			for emp in emp_arr:
		
				loc = searchLocation(locations, emp["zone"])
				result = dict()
				result["basic_emp_info"] = emp
				if detect_loc:
					where = whereEmp(emp["zone"], emp["uid"])
					result["last_known_location"] = where
				result["location_url"] = "https://portal-ua.globallogic.com/officetime/#table/"+emp["zone"]+"/"+str(emp["uid"])+"/week/0"
				
				if timestamp_days > 0:
					result["worked_hours"] = getEmpWorkingHours(emp["zone"], emp["uid"], round(timestamp_from), round((datetime.now()).timestamp() * 1000))
					
				if loc != None:
					seats = searchSeat(loc, emp["first_name"], emp["last_name"])
					if seats != None:
						result["seats"] = seats
						if (len(seats) > 0):
							if open==True:
								webbrowser.open(result["seats"][0]["emp_office_url"])
								webbrowser.open(result["seats"][0]["glo_url"])
								webbrowser.open(result["seats"][0]["ext_info"]["portal_link"])
								webbrowser.open(result["location_url"])
				json.append(result)
	
	return json


def load_cache(cache_name):
	try:
		fp = open(cache_name, 'r')
		return json.load(fp)
		
	except Exception as ex:
		return dict()
		
def save_cache(cache_name, cache_dict):
	try:
		fp = open(cache_name, 'w')
		json.dump(cache_dict, fp, sort_keys=True, indent=4, separators=(',', ': '))
		
	except Exception as ex:
		pass
		
def searchByName(args, open=False, detect_loc=True, working_hours_period = 0):
	employees = getALLEmp()
	
	if len(args) == 2:
		first_name, second_name = args
		emps = findEmpN(employees, first_name, second_name)
	else:
		emps = findEmpS(employees, args[0])
	res = summaryResults(emps, open, detect_loc, working_hours_period)
	return res
		
	
def searchEmpsByProject(project_name, detect_loc, working_hours_period):
	res = []
	employees = getALLEmp()
	locations = getAllLocations(headers_map)
	timestamp_days = int(working_hours_period[0])
	
	timestamp_from = 0
	if  timestamp_days > 0:
		timestamp_from = (datetime.now() - timedelta(days=timestamp_days)).timestamp() * 1000
	
	for emp in employees:
		loc = searchLocation(locations, emp["zone"])
		if loc != None:
			seats = searchSeat(loc,  emp["first_name"], emp["last_name"])
			if seats != None:
					for seat in seats:
						if (seat["emp_info"]["client"]["project"]["name"].find(str(project_name)) != -1) or \
							(seat["emp_info"]["client"]["name"].find(str(project_name)) != -1):
							el = dict()
					
							el["basic_emp_info"] = emp
							el["location_url"] = "https://portal-ua.globallogic.com/officetime/#table/"+emp["zone"]+"/"+str(emp["uid"])+"/week/0"
							if detect_loc:
								where = whereEmp(emp["zone"], emp["uid"])
								el["last_known_location"] = where
								
							el["seats"] = seats	
							
							if  timestamp_days > 0:
								el["worked_hours"] = getEmpWorkingHours(emp["zone"], emp["uid"], round(timestamp_from), round((datetime.now()).timestamp() * 1000))
	
								if (round(timestamp_from) > round(seat["ext_info"]["joining_time"] * 1000)):
									el["do_not_stat"] = False
								else:
									el["do_not_stat"] = True
									
								#print(round(timestamp_from))
								#print(round(int(seat["ext_info"]["joining_time"]) * 1000))	
								#print(el["do_not_stat"] )

							res.append(el)
							break

	return res
	
def workHoursToMinutes(wh_str):
	return round(int(wh_str[:wh_str.find(":")]) * 60) + int(wh_str[wh_str.find(":") + 1:])
	
def compareWHours(emp_a, emp_b):
	if (emp_a == None) or (emp_b == None) or (emp_a["worked_hours"] == None) or (emp_b["worked_hours"] == None):
		return -2

	wh_a = workHoursToMinutes(emp_a["worked_hours"])
	wh_b = workHoursToMinutes(emp_b["worked_hours"])
	
	if wh_a > wh_b:
		return 1
		
	elif wh_a == wh_b:
		return 0
	
	else:
		return -1


def shortInformWH(emps):
	res = []
	for emp in emps:
		el = dict()
		el["first_name"] = emp["basic_emp_info"]["first_name"]
		el["last_name"] = emp["basic_emp_info"]["last_name"]
		el["location_url"] = emp["location_url"]
		el["worked_hours"] = emp["worked_hours"]
		el["band"] = emp["seats"][0]["ext_info"]["band"]
		res.append(el)

	return res
	
# asc = -1, desc = 1
def sortBy(emps, count, cval):
	res = []
	if count > len(emps):
		count = len(emps)
		
	for x in range(count):
		if emps[x]["worked_hours"] != None:
			if (emps[x] not in res) and (emps[x]["do_not_stat"] == False):
				cmp_perf = emps[x]
				for emp in emps:
					if (emp not in res) and (emp["do_not_stat"] == False):
						if compareWHours(cmp_perf, emp) == cval:
							cmp_perf = emp
							
				res.append(cmp_perf)
				

	return shortInformWH(res)
	
def shortInfoJT(emps):
	res = []
	for emp in emps:
		el = dict()
		el["first_name"] = emp["basic_emp_info"]["first_name"]
		el["last_name"] = emp["basic_emp_info"]["last_name"]
		el["joining_time"] = (datetime.fromtimestamp(emp["seats"][0]["ext_info"]["joining_time"])).strftime('%Y/%m/%d %H:%M:%S')
		el["band"] = emp["seats"][0]["ext_info"]["band"]
		res.append(el)

	return res
	
	
def compareJTime(emp_a, emp_b):
	time_a = emp_a["seats"][0]["ext_info"]["joining_time"] 
	time_b = emp_b["seats"][0]["ext_info"]["joining_time"] 
	
	if time_a > time_b:
		return 1
	elif time_a == time_b:
		return 0
		
	return -1
	
def joining_time_sort(emps, count, cval):
	res = []
	if count > len(emps):
		count = len(emps)
		
	for x in range(count):
		if emps[x]["seats"][0]["ext_info"]["joining_time"] != None:
			if (emps[x] not in res):
				cmp_perf = emps[x]
				for emp in emps:
					if (emp not in res):
						if compareJTime(cmp_perf, emp) == cval:
							cmp_perf = emp
							
				res.append(cmp_perf)
	
	
	return shortInfoJT(res)
	
def joining_time_stat(emps):
	res = dict()
	
	res["oldest"] = joining_time_sort(emps, 10, 1)
	res["newest"] = joining_time_sort(emps, 10, -1)
	
	return res
	
def calcQuartile(emps):
	tmp = sortBy(emps, len(emps), -1)
	return emps[round(len(emps) // 2)]["worked_hours"]
	
def avgWorkHours(emps):
	a = 0
	count = 0
	for emp in emps:
		if (emp["worked_hours"] != None) and (emp["do_not_stat"] == False):
			count +=1
			a += workHoursToMinutes(emp["worked_hours"])
		
	a = a // count
	hours = a // 60
	minutes = a % 60
	
	return ("%s:%s" % (str(hours), str(minutes)))
	
def calcStatProj(emps, timestamp_days):
	res = dict()
	res["days"] = timestamp_days
	res["top_workers"] = sortBy(emps, 10, -1)
	res["worst_workers"] = sortBy(emps, 10, 1)
	res["quartile"] = calcQuartile(emps)
	res["avg"] = avgWorkHours(emps)

	return res
	
def calcBands(emps):
	res = dict()
	
	for emp in emps:
		try:
			res[emp["seats"][0]["ext_info"]["band"]] += 1
		except:
			res[emp["seats"][0]["ext_info"]["band"]] = 1
	
	return res
	
def zoneStat(emps):
	res = dict()
	
	for emp in emps:
		try:
			res[emp["basic_emp_info"]["zone"]] += 1
		except:
			res[emp["basic_emp_info"]["zone"]]  = 1

	return res
	
def locStat(emps):
	res = dict()
	
	for emp in emps:
		try:
			res[emp["basic_emp_info"]["zone"]+"_"+emp["seats"][0]["loc_info_ext"]["block_name"]] += 1
		except:
			res[emp["basic_emp_info"]["zone"]+"_"+emp["seats"][0]["loc_info_ext"]["block_name"]] = 1

	return res
	
def searchByProject(project_name, detect_loc, working_hours_period):
	res = dict()
	
	project_str = ' '.join(project_name)
	emps = searchEmpsByProject(project_str, detect_loc, working_hours_period)
	if len(emps) == 0:
		return res
		
	res["employees"] = emps
	res["total"] = len(emps)
	
	timestamp_days = int(working_hours_period[0])
	if (timestamp_days > 0):
		res["worked_hours_stat"] = calcStatProj(emps, timestamp_days)
		
	res["bands_stat"] = calcBands(emps)
	res["zone_stat"] = zoneStat(emps)
	res["loc_stat"] = locStat(emps)
	res["old_new"] = joining_time_stat(emps)


	return res
	

def searchEmpByUsername(username):
	employees = getALLEmp()
	locations = getAllLocations(headers_map)
	zone = ""
	for emp in employees:
		#No zone list. Consider sepparate zone list generation to make part more understandable
		if zone != emp["zone"]:
			zone = emp["zone"]
			loc = searchLocation(locations, emp["zone"])
			if loc != None:
				seats = searchSeatUsername(loc,  username)
				if len(seats) != 0:
					el = dict()
					el["seats"] = seats	
					first_name = seats[0]["ext_info"]["first_name"]
					last_name = seats[0]["ext_info"]["last_name"]
					for emp in employees:
						if (emp['first_name'] == first_name) and (emp['last_name'] == last_name):
							el["last_known_location"] = whereEmp(emp["zone"], emp["uid"])
							el["basic_emp_info"] = emp
							el["location_url"] = "https://portal-ua.globallogic.com/officetime/#table/"+emp["zone"]+"/"+str(emp["uid"])+"/week/0"
			
					return el


def isBearerExpired(bearer):
	if bearer == None:
		return True
		
	exp_date = datetime.fromtimestamp(bearer["expired_time"])
	if exp_date < datetime.now():
		return True
	
	return False
	
def init_caches():
	global place_info
	global loc_info
	global emp_info
	global locations_all
	global emp_all
	
	place_info=load_cache('places.json')
	loc_info=load_cache('loc_info.json')
	emp_info=load_cache('emp_info.json')
	locations_all=load_cache('locations.json')
	emp_all=load_cache('emp_all.json')
	
def save_caches():
	try:
		save_cache('places.json', place_info)
		save_cache('loc_info.json', loc_info)
		save_cache('emp_info.json', emp_info)
		save_cache('locations.json', locations_all)
		save_cache('emp_all.json', emp_all)
	except KeyboardInterrupt:
		pass	

def load_settings():
	settings = load_cache('settings.json')
	try:
		headers_map['Authorization'] = 'Bearer '+settings['bearer']['bearer']
		headers['Authorization'] = settings['basic']
	except:
		pass
		
	return settings
	
	
	
def save_settings(settings):
	try:
		save_cache('settings.json', settings)
	except KeyboardInterrupt:
		pass	
		
		
def refresh_auth(user_name, password):
	settings = dict()
	basic = authBasic("https://portal-ua.globallogic.com/officetime", user_name, password)
	bearer = authBearer(user_name, password)
	if (basic != None) and (bearer != None):
		settings['bearer'] = bearer
		settings['basic'] = basic
		settings['username'] = user_name
		settings['password'] = password
		headers_map['Authorization'] = 'Bearer '+settings['bearer']['bearer']
		headers['Authorization'] = settings['basic']
		save_settings()
		return settings