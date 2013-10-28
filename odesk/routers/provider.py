# Python bindings to oDesk API
# python-odesk version 0.5
# (C) 2010-2013 oDesk

from odesk.namespaces import Namespace


class Provider(Namespace):
    api_url = 'profiles/'
    version = 1

    def get_provider(self, provider_ciphertext):
        """
        Retrieve an exhaustive list of attributes associated with the \
        referenced provider.

        *Parameters:*
          :provider_ciphertext:   The provider's cipher text (key)

        """
        if isinstance(provider_ciphertext, (list, tuple)):
            provider_ciphertext = map(str, provider_ciphertext)
            provider_ciphertext = ';'.join(provider_ciphertext[:20])

        url = 'providers/{0}'.format(provider_ciphertext)
        result = self.get(url)
        return result.get('profile', result)

    def get_provider_brief(self, provider_ciphertext):
        """
        Retrieve an brief list of attributes associated with the \
        referenced provider.

        *Parameters:*
          :provider_ciphertext:   The provider's cipher text (key)

        """
        if isinstance(provider_ciphertext, (list, tuple)):
            provider_ciphertext = map(str, provider_ciphertext)
            provider_ciphertext = ';'.join(provider_ciphertext[:20])

        url = 'providers/{0}/brief'.format(provider_ciphertext)
        result = self.get(url)
        return result.get('profile', result)

    def search_providers(self, data=None, page_offset=0, page_size=20,
                         order_by=None):
        """
        Search oDesk providers.

        *Parameters:*
          :data:       A dict of the following parameters
                     (all parameters are optional):

              :q:     Search query, e.g. "python".
                      Any text that appears in a provider's profile

              :c1:    Category name. Use Metadata API to get the list
                      of currently valid categories

              :c2:    Subcategory, which is related to category (c1),
                      please use c2[] to specify a couple subcategories

              :fb:    Feedback (adjusted score),
                      e.g. ``fb='2.0 - 2.9 Stars'``
                      This searches for providers who have an adjusted
                      feedback score equal or greater (up to 5) than the number
                      passed in this parameter (decimals are okay).

              :hrs:     (Total hours) This searches for providers who have
                      a total number of hours equal or greater to the number
                      passed in this parameter.

              :ir:    This boolean parameter is used in combination with
                      the total hours worked parameter, and searches providers
                      who have worked within the last six months.
                      "Yes" or "No" are the only valid searches.
                      Omitting this will default to 'No'.

              :min:   The provider's minimum rate they have charged
                      in the past. Excludes providers with a public rate
                      less than this amount.

              :max:     The provider's maximum rate they have charged
                      in the past. Excludes providers with a public rate
                      greater than this amount.

              :loc:   Country region. Limit your searches to a
                      specific country region. Possible values:
                          * 'Australasia'
                          * 'East Asia'
                          * 'Eastern Europe'
                          * 'North America'
                          * 'South Asia'
                          * 'Western Europe'
                          * 'Misc'

              :pt:    Provider type. Limit your search to independent
                      or affiliate providers. Possible values:
                          * 'Individual'
                          * 'Affiliated'
                      By default both types are returned.

              :last:  Limit your search to providers who were active
                      after the date passed in this parameter.
                      Dates should be formatted like: 07-13-2009

              :test:  Limit your search to providers who have passed
                      a specific test (based on the test id).
                      You can get available tests using
                      :py:meth:`~odesk.routers.provider.Provider.get_tests_metadata`
                      Only singe value is allowed.

              :port:  Limit your search to providers who have at least
                      this number of portfolio items.

              :rdy:   Only return oDesk ready providers.

              :eng:   Limit your results to providers who have
                      at least the rating passed in the parameter.
                      Only the following English levels are available
                      (no decimals): [1,2,3,4,5]

              :ag:    Agency reference. Limit your search to a specific agency.

              :to:    Search the provider profile title text only.
                      Possible values: 'yes'|'no', by default 'no'.

              :g:     Limit your search to a specific group.

              :skills:  Required skills. A name of the skill.
                        Multiple values are allowed as a comma-separated string

          :page_offset: Start of page (number of results to skip) (optional)

          :page_size:   Page size (number of results) (optional: default 20)

          :order_by:  Sorting, in format
                      $field_name1;$field_name2;..$field_nameN;AD...A,
                      where 'A' means ascending, 'D' means descending,
                      the only available sort field as of now is "Date Created"

        """
        url = 'search/providers'
        if data is None:
            data = {}

        data['page'] = '{0};{1}'.format(page_offset, page_size)
        if order_by is not None:
            data['sort'] = order_by
        result = self.get(url, data=data)
        return result.get('providers', result)

    def search_jobs(self, data=None,
                    page_offset=0, page_size=20, order_by=None):
        """
        Search oDesk jobs.

        *Parameters:*
          :data:        A dict of the following parameters
                        (all parameters are optional):

              :q:       Query, e.g. "python",
                        search the text of the job's description.

              :c1:      Category name. Use Metadata API to get the list
                        of currently valid categories

              :c2:      Subcategory, which is related to category (c1),
                        please use c2[] to specify a couple subcategories

              :qs:      Skill required, single value or comma-separated list

              :fb:      Feedback (adjusted score). Limit your search to buyers
                        with at least a score of the number passed in this
                        parameter. Use the following values to filter by score:
                            * none = '0'
                            * 1 - 4 Scores = '10'
                            * 4 - 4.5 Scores = '40'
                            * 4.5 - 5 Scores = '45'
                            * 5.0 Scores = '50'

              :min:     Minimum budget

              :max:     Maximum budget

              :t:       Job type. Possible values are:
                            * 'Hourly'
                            * 'Fixed'

              :wl:      Hours per week. This parameter can only be used when
                        searching Hourly jobs. These numbers are
                        a little arbitrary, so follow the following parameters
                        in order to successfully use this parameter:
                            * As Needed < 10 Hours/Week = '0'
                            * Part Time: 10-30 hrs/week = '20'
                            * Full Time: 30+ hrs/week = '40'

              :dur:     Engagement duration. This parameter can only be used
                        when searching Hourly jobs. These numbers are
                        a little arbitrary, so follow the following parameters
                        in order to successfully use this parameter:
                            * Ongoing / More than 6 months = '26'
                            * 3 to 6 months = '13'
                            * 1 to 3 months = '4'
                            * Less than 1 month = '1'
                            * Less than 1 week = '0'

              :dp:      Date posted. Search jobs posted according to timeframe.
                        Use the following parameters to specify a timeframe:
                            * Any Timeframe  = empty
                            * Last 24 hours = '0'
                            * Last 24 hours - 3 Days = '1'
                            * Last 3-7 Days = '3'
                            * Last 7-14 Days - '7'
                            * Last 14-30 Days - '14'
                            * > 30 Days - '30'

              :st:      Job status. Search for Canceled jobs, In Progress Jobs
                        and Completed Jobs. Defaults to Open Jobs.
                        Possible values:
                            * Open Jobs = 'Open'
                            * Jobs in Progress = 'In Progress'
                            * Completed Jobs = 'Completed'
                            * Canceled Jobs = 'Cancelled'

              :tba:     Total billed assignments.
                        Limit your search to buyers who completed at least
                        this number of paid assignments. Possible values:
                            * none = '0'
                            * has 1-5 billed assignments = '1'
                            * has 5-10 billed assignments = '5'
                            * has >10 billed assignments = '10'

              :gr:      Preferred group. Limits your search to buyers
                        in a particular group

              :to:        Search the provider profile title text only.
                        Possible values: 'yes'|'no', by default 'no'.

          :page_offset:   Start of page (number of results to skip) (optional)

          :page_size:     Page size (number of results) (optional: default 20)

          :order_by:      Sorting, in format
                        ``$field_name1;$field_name2;..$field_nameN;AD...A``,
                        where A means 'Ascending', D means 'Descending',
                        e.g. ``date_posted;A``

        """
        url = 'search/jobs'
        if data is None:
            data = {}
        data['page'] = '{0};{1}'.format(page_offset, page_size)
        if order_by is not None:
            data['sort'] = order_by
        result = self.get(url, data=data)
        return result.get('jobs', result)

    def get_categories_metadata(self):
        """
        Returns list of all categories available for job/contractor profiles.

        """
        url = 'metadata/categories'
        result = self.get(url)
        return result.get('categories', result)

    def get_skills_metadata(self):
        """
        Returns list of all skills available for job/contractor profiles.

        """
        url = 'metadata/skills'
        result = self.get(url)
        return result.get('skills', result)

    def get_regions_metadata(self):
        """
        Returns list of all region choices available for \
        job/contractor profiles.

        """
        url = 'metadata/regions'
        result = self.get(url)
        return result.get('regions', result)

    def get_tests_metadata(self):
        """
        Returns list of all available tests at oDesk.

        """
        url = 'metadata/tests'
        result = self.get(url)
        return result.get('tests', result)
