from __future__ import print_function
import odesk
from six import input
from pprint import pprint


def web_based_app():
    """Emulation of web-based app.
    Your keys should be created with project type "Web".

    Returns: ``odesk.Client`` instance ready to work.

    """
    print("Emulating web-based app")

    public_key = input('Please enter public key: > ')
    secret_key = input('Please enter secret key: > ')

    #Instantiating a client without an auth token
    client = odesk.Client(public_key, secret_key)

    print("Please to this URL (authorize the app if necessary):")
    print(client.auth.get_authorize_url())
    print("After that you should be redirected back to your app URL with "
          "additional ?oauth_verifier= parameter")

    verifier = input('Enter oauth_verifier: ')

    oauth_access_token, oauth_access_token_secret = \
        client.auth.get_access_token(verifier)

    # Instantiating a new client, now with a token.
    # Not strictly necessary here (could just set `client.oauth_access_token`
    # and `client.oauth_access_token_secret`), but typical for web apps,
    # which wouldn't probably keep client instances between requests
    client = odesk.Client(public_key, secret_key,
                          oauth_access_token=oauth_access_token,
                          oauth_access_token_secret=oauth_access_token_secret)

    return client


if __name__ == '__main__':
    client = web_based_app()

    try:
        print("My info")
        pprint(client.auth.get_info())
        print("Team rooms:")
        pprint(client.team.get_teamrooms())
        #HRv2 API
        print("HR: companies")
        pprint(client.hr.get_companies())
        print("HR: teams")
        pprint(client.hr.get_teams())
        print("HR: userroles")
        pprint(client.hr.get_user_roles())
        print("Get jobs")
        pprint(client.provider.search_jobs({'q': 'python'}))
    except Exception as e:
        print("Exception at %s %s" % (client.last_method, client.last_url))
        raise e
