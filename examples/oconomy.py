"""
Python bindings to odesk API
python-odesk version 0.1
(C) 2010 oDesk
"""
import odesk
from datetime import date

PUBLIC_KEY = None
SECRET_KEY = None

#TODO: Desktop app example (check if it's working at all - wasn't last time)

def oconomy(public_key, secret_key):
    print "Emulating web-based app"
    #Instantiating a client without an auth token
    client = odesk.Client(public_key, secret_key)
    print "Please to this URL (authorize the app if necessary):"
    print client.auth.auth_url()
    print "After that you should be redirected back to your app URL with " + \
          "additional ?frob= parameter"
    frob = raw_input('Enter frob: ') 
    auth_token, user = client.auth.get_token(frob)
    print "Authenticated user:"
    print user
    #Instantiating a new client, now with a token. 
    #Not strictly necessary here (could just set `client.auth_token`), but 
    #typical for web apps, which wouldn't probably keep client instances 
    #between requests
    client = odesk.Client(public_key, secret_key, auth_token)
    print client.oconomy.get_summary(2010,12)
    
    print client.oconomy.get_hours_worked_by_locations()
    print client.oconomy.get_hours_worked_by_weeks()
    print client.oconomy.get_top_countries_by_hours()
    print client.oconomy.get_charges_by_categories()
    print client.oconomy.get_most_requested_skills()
    
    print client.gds_oconomy.get_summary(2010,12)
    
    print client.gds_oconomy.get_hours_worked_by_locations()
    print client.gds_oconomy.get_hours_worked_by_weeks()
    print client.gds_oconomy.get_top_countries_by_hours()
    print client.gds_oconomy.get_charges_by_categories()
    print client.gds_oconomy.get_most_requested_skills()

    print "monthly summary"
    print client.oconomy.get_monthly_summary('201011')
    print "hours worked by locations"
    print client.oconomy.get_hours_worked_by_locations()
    print "hours worked by weeks"
    print client.oconomy.get_hours_worked_by_weeks()
    print "top countries by hours"
    print client.oconomy.get_top_countries_by_hours()
    print "earnings by categories"
    print client.oconomy.get_earnings_by_categories()
    print "most requested skills"
    print client.oconomy.get_most_requested_skills()
    
 
if __name__ == '__main__':
    public_key = PUBLIC_KEY or raw_input('Enter public key: ')
    secret_key = SECRET_KEY or raw_input('Enter secret key: ')

    oconomy(public_key, secret_key)
