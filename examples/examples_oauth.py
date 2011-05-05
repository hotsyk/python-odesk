"""
Python bindings to odesk API
python-odesk version 0.1
(C) 2010 oDesk
"""
import odesk

PUBLIC_KEY = None
SECRET_KEY = None


#TODO: Desktop app example (check if it's working at all - wasn't last time)

def web_based_app(public_key, secret_key):
    print "Emulating web-based app"
    #Instantiating a client without an auth token
    client = odesk.Client(public_key, secret_key, auth='oauth')
    print "Please to this URL (authorize the app if necessary):"
    print client.auth.get_authorize_url()
    print "After that you should be redirected back to your app URL with " + \
          "additional ?oauth_verifier= parameter"
    verifier = raw_input('Enter oauth_verifier: ')
    oauth_access_token, oauth_access_token_secret = client.auth.get_access_token(verifier)
    #Instantiating a new client, now with a token.
    #Not strictly necessary here (could just set `client.oauth_access_token`
    #and `client.oauth_access_token_secret`), but typical for web apps,
    #which wouldn't probably keep client instances between requests
    client = odesk.Client(public_key, secret_key, auth='oauth',
                        oauth_access_token=oauth_access_token,
                        oauth_access_token_secret=oauth_access_token_secret)

    try:
        print "Team rooms:"
        print client.team.get_teamrooms()
        #HRv2 API
        print "HR: companies"
        print client.hr.get_companies()
        print "HR: teams"
        print client.hr.get_teams()
        print "HR: offers"
        print client.hr.get_offers()
        print "HR: get_engagements"
        print client.hr.get_engagements()
        print "HR: userroles"
        print client.hr.get_user_role()
        print "HR: candidacy stats"
        print client.hr.get_candidacy_stats()
        print "Get jobs"
        print client.provider.get_jobs({'q': 'python'})
        print "Financial: withdrawal methods"
        print client.finance.get_withdrawal_methods()
    except Exception, e:
        print "Exception at %s %s" % (client.last_method, client.last_url)
        raise e



if __name__ == '__main__':
    public_key = PUBLIC_KEY or raw_input('Enter public key: ')
    secret_key = SECRET_KEY or raw_input('Enter secret key: ')

    web_based_app(public_key, secret_key)

