import json
import libgl
import argparse
import sys

def get_pretty_print(json_object):
	return json.dumps(json_object, sort_keys=True, indent=4, separators=(',', ': '))
	
def main():
	
	parser = argparse.ArgumentParser()
	parser.add_argument('-s', nargs='*', metavar="name of an employee", help="Find all information about given employee")
	parser.add_argument('-o', action='store_true', help='Open employee\'s information in the browser')
	parser.add_argument('-p', nargs='*', metavar="name of the project", help="Find all information about given project/client" )
	parser.add_argument('-w', action='store_true', help='Skip location detection')
	parser.add_argument('-t', nargs=1, default=[0], metavar="days", help="Calculate working hours for employee for the period of the last n days" )
	parser.add_argument('-l', nargs=2, metavar="login password", help="Set login and password for auth on globallogic's resources" )
	parser.add_argument('-u', nargs=1, metavar="username", help="Find by username")

	args = parser.parse_args()
	settings = libgl.load_settings()

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

	if args.s != None:
		if len(args.s) > 0:
			res = libgl.searchByName(args.s, args.o, not args.w, args.t)
			print(get_pretty_print(res))

	if args.p != None:
		if len(args.p) > 0:
			res = libgl.searchByProject(args.p, not args.w, args.t)
			print(get_pretty_print(res))
			
	if args.u != None:
		if len(args.u) > 0:
			res = libgl.searchEmpByUsername(args.u[0])
			print(get_pretty_print(res))

	libgl.save_settings(settings)
	libgl.save_caches()
	


	
if __name__ == "__main__":
    main()

