import selenium
from selenium.webdriver.common.keys import Keys
from selenium import webdriver
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
import time
import json
import libgl
import argparse
import sys
import requests

from datetime import datetime, timedelta

def grepErpDateOptions(cont):
	res = []
	pos = 0
	searchText = "value=\""
	while pos != -1:
		pos = cont.find(searchText)
		cont = cont[pos + len(searchText):]
		pos = cont.find("\">")
		if pos != -1:
			el = dict()
			val = cont[:pos]
			cont = cont[pos+2:]
			pos = cont.find("</option>")
			if pos == -1:
				break
			name = cont[:pos]
			el['key'] = val
			el['date'] = name
			res.append(el)
			cont = cont[pos:]
			
		else:
			break
			
			
	return res
	

def getErpDates(cookies):
	searchText = "TimecardPeriodList\">"
	response = requests.get('https://erp.globallogic.com/OA_HTML/RF.jsp?function_id=16744&resp_id=50680&resp_appl_id=800&security_group_id=0&lang_code=US', headers=libgl.headers_erp, cookies=cookies, verify=False)
	libgl.headers_erp['Referer'] = response.request.url
	if response.status_code == 200:
		cont = str(response.content)
		pos_b = cont.find(searchText)
		if (pos_b != -1):
			cont = cont[pos_b + len(searchText):]
			pos_b = cont.find("</select>")
			cont = cont[:pos_b]
			res = grepErpDateOptions(cont)
			return res
			
			
def selectErpPeriod(dates, now):
	format = '%Y/%m/%d'
	counter = 0
	for date in dates:
		counter += 1
		pos_b = date['key'].find("|")
		start = datetime.strptime(date['key'][:pos_b], format)
		if pos_b != -1:
			end = datetime.strptime(date['key'][pos_b+1:pos_b + 11], format)
			if now >= start and now <= (end + timedelta(hours = 24)):
				res = dict()
				res['start'] = start
				res['end'] = end
				res['el'] = date
				res['counter'] = counter
				return res
	
def parseEmpWhForPeriod(emp, period):
	res = []
	searchText = "<div class=\"tr totalforday cf\" data-day=\""
	searchText2 = "th td3\">"
	searchText3 = "</div>"
	format = '%d.%m.%Y'
	
	start = round(period['start'].timestamp() * 1000)
	end = round(period['end'].timestamp() * 1000)
	raw = libgl.getEmpWorkingHoursRaw(emp["basic_emp_info"]["zone"], emp["basic_emp_info"]["uid"], start, end)
	
	if raw == None:
		return None
	
	pos = 0
	while pos != -1:
		pos = raw.find(searchText)
		if pos == -1:
			break
		
		raw = raw[pos+len(searchText):]
		pos = raw.find("\"")
		if pos == -1:
			break
			
		date = raw[:pos]
		raw = raw[pos + 1:]
		pos = raw.find(searchText2)
		if pos == -1:
			break
		
		raw = raw[pos + len(searchText2):]
		pos = raw.find(searchText3)
		if pos == -1:
			break
			
		val = raw[:pos]
		raw = raw[pos + len(searchText3):]
		
		el = dict()
		el['date'] = datetime.strptime(date, format)
		el['val']  = [ int(x) for x in val.split(":") ]
		res.append(el)

	return res
	
def checkFor(username, erp_cookies, now):
	print("Get erp dates...")
	dates = getErpDates(erp_cookies)
	if (dates == None):
		print('Err getErpDates')
		return 
	
	print("searchEmpByUsername for "+ username +"... ")
	emp = libgl.searchEmpByUsername(username)
	if (emp == None):
		print('Err searchEmpByUsername')
		return
	
	print("selectErpPeriod")
	period = selectErpPeriod(dates, now)
	if (period == None):
		print('Err period')
		print(dates)
		return
	
	print("parseEmpWhForPeriod")
	wh = parseEmpWhForPeriod(emp, period)
	if (wh == None):
		print('Err parseEmpWhForPeriod')
		return
	
	return list((period, wh))


def login(username, password, hide):
	if hide == True:
		options = webdriver.ChromeOptions()
		options.add_argument('headless')
		options.add_argument('window-size=1920x1080')
		options.add_argument("disable-gpu")
		driver = webdriver.Chrome('chromedriver', options=options)
	else:
		driver = webdriver.Chrome()
		
	driver.get("https://erp.globallogic.com/OA_HTML/AppsLocalLogin.jsp?langCode=US")
	try:
		username_form = driver.find_element_by_name('usernameField')
		password_form = driver.find_element_by_name('passwordField')
		button = driver.find_element_by_xpath('//button[@message="FND_SSO_LOGIN"]')
		username_form.send_keys(username)
		password_form.send_keys(password)
		

		button.click()
	except Exception as e:
		print (str(e))
		driver.close()
		return None
		
	
	return driver
	
def pressButtonPL(driver, text):
	try:
		button = driver.find_element_by_partial_link_text(text)
		button.click()
		print(button)
	except Exception as e:
		print (str(e))
		driver.close()
		return None
		
	return driver
	
def pressButtonX(driver, xpath):
	try:
		button = driver.find_element_by_xpath(xpath)
		button.click()
		print(button)
	except Exception as e:
		print (str(e))
		driver.close()
		return None
		
	return driver
	
def newTimecard(driver):
	element = WebDriverWait(driver, 120).until(EC.presence_of_element_located((By.PARTIAL_LINK_TEXT, 'HR - Employee Self Service - Ukraine')))
	element.click()
		
	driver = pressButtonPL(driver, "Timesheet")
	if driver == None:
		return
	
	driver = pressButtonPL(driver, "Create Timecard")
	if driver == None:
		return

	return driver
	
def selectPeriod(driver, period):
	driver = pressButtonX(driver, "//select[@name='TimecardPeriodList']/option[text()='"+period['el']['date']+"']")
	if driver == None:
		return

	return driver
	
	
def selectTemplate(driver, template):
	driver = pressButtonX(driver, "//select[@name='TemplateList']/option[text()='"+template+"']")
	if driver == None:
		return
		
	driver = pressButtonX(driver, '//input[@title="Overwrite Entry"]')
	if driver == None:
		return
	
	driver = pressButtonX(driver, '//button[@title="Apply Template"]')
	if driver == None:
		return
		
	return driver
	
def fillEl(driver, id, value):
	print("Set "+str(id) + " = " + str(value))
	try:
		button = driver.find_element_by_id(id)
		button.clear()
		button.send_keys(value)
	except Exception as e:
		print (str(e))
		driver.close()
		return None
		
	return driver
	
def getEl(driver, id):
	value = None
	try:
		el = driver.find_element_by_id(id)
		value = el.get_attribute("value")
	except Exception as e:
		print (str(e))
		driver.close()
		return None
		
	print("Get "+str(id) + " = " + str(value))
	return list((driver, value))
	
def fillformS(driver, wh, period):
	counter = 0
	for day in wh:
		if (day['date'].weekday != 5) or (day['date'].weekday != 6):
			if ((period['start'] + timedelta(days = counter)) == day['date']):
				val = 8
				if (day['val'][0] < 4):
					val = 4
					
				if (day['val'][0] != 0):
					driver = fillEl(driver, 'B22_1_'+str(counter), val)
					if driver == None:
						return None
					
		counter += 1
	
	driver = pressButtonX(driver, '//button[@title="Save"]')
	
	return driver
	
def getInputs(driver):
	res = []
	for x in range(1,10):
		try:
			driver, val = getEl(driver, "B22_"+str(x)+"_0")
			if (val == None) or (len(val) == 0):
				break
			
			res.append(val)
		except Exception as e:
			print (str(e))
			driver.close()
			return None
		
	return list((driver, res))
	
def fillformM(driver, wh, period, inputs):
	counter = 0
	
	#in case if period starts from Sat/Sun
	for x in range(len(inputs)):
		fillEl(driver, 'B22_'+str(x+1)+'_0', 0)
	
	for day in wh:
		if (day['date'].weekday != 5) or (day['date'].weekday != 6):
			print(day)
			while ((period['start'] + timedelta(days = counter)) != day['date']):
				print((period['start'] + timedelta(days = counter)))
				counter += 1
				for x in range(len(inputs)):
					fillEl(driver, 'B22_'+str(x+1)+'_'+str(counter), 0)
			
			print((period['start'] + timedelta(days = counter)))
			val = 8
			if (day['val'][0] < 4):
				val = 4
				
			if (day['val'][0] != 0):
				for x in range(len(inputs)):
					driver = fillEl(driver, 'B22_'+str(x+1)+'_'+str(counter), round((int(inputs[x])/8) * val))
					if driver == None:
						return None


	driver.save_screenshot("screenshot.png")
	driver = pressButtonX(driver, '//button[@title="Save"]')
	driver.save_screenshot("screenshot2.png")

	return driver
	
	
def fillFor(username, password, period, wh, hide = True):
	driver = login(username, password, hide)
	if driver == None:
		return
		
	driver = newTimecard(driver)
	if driver == None:
		return
		
	driver = selectPeriod(driver, period)
	if driver == None:
		return
		
	driver = selectTemplate(driver, " -   MAIN_TEMPLATE")
	if driver == None:
		return
	
	try:
		driver, inputs = getInputs(driver)
	except:
		return
		
	driver = fillformM(driver, wh, period, inputs)
	if driver == None:
		return

	return driver
	
def main():
	parser = argparse.ArgumentParser()
	parser.add_argument('-l', nargs=2, metavar="login password", help="Set login and password for auth on globallogic's resources" )
	parser.add_argument('-w', action='store_false', default=True, help='Show browser window')
	parser.add_argument('-d', nargs=3, metavar="%b %d %Y", help="Date. Fill for given date period. Ex. -d Sep 30 2019")

	args = parser.parse_args()
	settings = libgl.load_settings()
	if args.d != None:
		date = datetime.strptime(' '.join(args.d), "%b %d %Y")
	else:
		date = datetime.now()

	if args.l != None:	
		settings = libgl.refresh_auth(args.l[0], args.l[1])
		if (settings == None):
			sys.exit('Authorization error(1)')
	
	if len(settings) == 0:
		sys.exit('Please provide login and password(see -l options)')
		
	if ('bearer' not in settings) or ('basic' not in settings):
		settings = libgl.refresh_auth(settings['username'], settings['password'])
		if (settings == None):
			sys.exit('Authorization error(2)')
	
	if libgl.isBearerExpired(settings['bearer']) == True:
		print("Bearer expired")
		settings['bearer'] =  libgl.authBearer(settings['username'], settings['password'])

	if (settings['bearer'] == None):
		sys.exit('Authorization error(bearer token refresh)')
	
	libgl.init_caches()
	libgl.fillAuth(settings)

	try:
		print("Log in ERP...")
		settings['erp_cookies'] = (libgl.authErp(settings['username'], settings['password']))
		if (settings['erp_cookies'] == None):
			sys.exit('Authorization error(erp_cookies refresh(1))')
		period, wh = checkFor(settings['username'], settings['erp_cookies'], date)
	except Exception as e:
		print (str(e))
		sys.exit('Error(3)')

	fillFor(settings['username'], settings['password'], period, wh, args.w)

	libgl.save_settings(settings)
	libgl.save_caches()



if __name__ == "__main__":
    main()
