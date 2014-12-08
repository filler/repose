package org.openrepose.services.ratelimit;

import org.apache.commons.lang3.tuple.Pair;
import org.openrepose.services.ratelimit.cache.CachedRateLimit;
import org.openrepose.services.ratelimit.cache.RateLimitCache;
import org.openrepose.services.ratelimit.config.*;
import org.openrepose.services.ratelimit.exception.OverLimitException;
import org.openrepose.services.ratelimit.utils.StringUtilities;
import org.slf4j.Logger;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class RateLimitingServiceImpl implements RateLimitingService {
    private static final Logger LOG = org.slf4j.LoggerFactory.getLogger(RateLimitingServiceImpl.class);

    public static final String GLOBAL_LIMIT_USER = "GlobalLimitUser";
    public static final String GLOBAL_LIMIT_GROUP = "GlobalLimitGroup";

    private final RateLimitCache cache;
    private final GlobalLimitGroup globalLimitGroup;
    private final RateLimitingConfigHelper helper;
    private final boolean useCaptureGroups;

    private RateLimiter rateLimiter;

    public RateLimitingServiceImpl(RateLimitCache cache, RateLimitingConfiguration rateLimitingConfiguration) {

        if (rateLimitingConfiguration == null) {
            throw new IllegalArgumentException("Rate limiting configuration must not be null.");
        }

        this.cache = cache;
        this.rateLimiter = new RateLimiter(cache);
        this.helper = new RateLimitingConfigHelper(rateLimitingConfiguration);
        this.globalLimitGroup = helper.getGlobalLimitGroup();
        useCaptureGroups = rateLimitingConfiguration.isUseCaptureGroups();
    }

    @Override
    public RateLimitList queryLimits(String user, List<String> groups) {

        if (StringUtilities.isBlank(user)) {
            throw new IllegalArgumentException("User required when querying rate limits.");
        }

        final Map<String, CachedRateLimit> cachedLimits = cache.getUserRateLimits(user);
        final ConfiguredLimitGroup configuredLimitGroup = helper.getConfiguredGroupByRole(groups);
        final RateLimitListBuilder limitsBuilder = new RateLimitListBuilder(cachedLimits, configuredLimitGroup);

        return limitsBuilder.toRateLimitList();
    }

    @Override
    public void trackLimits(String user, List<String> groups, String uri, Map<String, String[]> parameterMap, String httpMethod, int datastoreWarnLimit) throws OverLimitException {

        if (StringUtilities.isBlank(user)) {
            throw new IllegalArgumentException("User required when tracking rate limits.");
        }

        final ConfiguredLimitGroup configuredLimitGroup = helper.getConfiguredGroupByRole(groups);
        final List< Pair<String, ConfiguredRatelimit> > matchingConfiguredLimits = new ArrayList<>();
        TimeUnit largestUnit = TimeUnit.SECOND;

        // Go through all of the configured limits for this group
        for (ConfiguredRatelimit rateLimit : configuredLimitGroup.getLimit()) {
            Matcher uriMatcher;
            if (rateLimit instanceof ConfiguredRateLimitWrapper) {
                uriMatcher = ((ConfiguredRateLimitWrapper) rateLimit).getRegexPattern().matcher(uri);
            } else {
                LOG.error("Unable to locate pre-built regular expression pattern in for limit group.  This state is not valid. "
                        + "In order to continue operation, rate limiting will compile patterns dynamically.");
                uriMatcher = Pattern.compile(rateLimit.getUriRegex()).matcher(uri);
            }

            // Did we find a limit that matches the incoming uri and http method?
            List<Matcher> queryParamMatchers = getQueryParamMatchers(rateLimit.getQueryParam(), parameterMap);
            if (uriMatcher.matches() && httpMethodMatches(rateLimit.getHttpMethods(), httpMethod) && queryParamMatchers != null) {
                matchingConfiguredLimits.add(Pair.of(LimitKey.getLimitKey(configuredLimitGroup.getId(),
                        rateLimit.getId(), uriMatcher, queryParamMatchers, useCaptureGroups), rateLimit));

                if (rateLimit.getUnit().compareTo(largestUnit) > 0) {
                    largestUnit = rateLimit.getUnit();
                }
            }
        }


        if (!matchingConfiguredLimits.isEmpty()) {
            rateLimiter.handleRateLimit(user, matchingConfiguredLimits, largestUnit, datastoreWarnLimit);
        }

        // Global Limits should be checked after user rate limits to avoid miscounts and DOS

        final List< Pair<String, ConfiguredRatelimit> > matchingGlobalConfiguredLimits = new ArrayList<>();
        largestUnit = TimeUnit.SECOND;
        for (ConfiguredRatelimit globalLimit : globalLimitGroup.getLimit()) {
            Matcher uriMatcher = ((ConfiguredRateLimitWrapper)globalLimit).getRegexPattern().matcher(uri);

            List<Matcher> queryParamMatchers = getQueryParamMatchers(globalLimit.getQueryParam(), parameterMap);
            if (uriMatcher.matches() && httpMethodMatches(globalLimit.getHttpMethods(), httpMethod) && queryParamMatchers != null) {
                matchingGlobalConfiguredLimits.add(Pair.of(LimitKey.getLimitKey(GLOBAL_LIMIT_GROUP,
                        globalLimit.getId(), uriMatcher, queryParamMatchers, useCaptureGroups), globalLimit)); // NOTE: GLOBAL_LIMIT_GROUP is not guaranteed to be unique since XSD validation does not enforce uniqueness as it does for other rate limit groups

                if (globalLimit.getUnit().compareTo(largestUnit) > 0) {
                    largestUnit = globalLimit.getUnit();
                }
            }
        }

        if (!matchingGlobalConfiguredLimits.isEmpty()) {
            rateLimiter.handleRateLimit(GLOBAL_LIMIT_USER, matchingGlobalConfiguredLimits, largestUnit, datastoreWarnLimit); // NOTE: GLOBAL_LIMIT_USER is not guaranteed to be unique
        }
    }

    private boolean httpMethodMatches(List<HttpMethod> configMethods, String requestMethod) {
        return configMethods.contains(HttpMethod.ALL) || configMethods.contains(HttpMethod.valueOf(requestMethod.toUpperCase()));
    }

    /**
     *
     * @param configuredQueryParams A <code>List</code> of the configured query parameter regexes.
     * @param requestParameterMap A <code>Map</code> of the key/value pairs in the request.
     * @return Returns a <code>List</code> of <code>Matcher</code> if the configured query parameters are all matched
     *         against the request query parameters. Otherwise, <code>null</code> is returned.
     */
    private List<Matcher> getQueryParamMatchers(List<QueryParam> configuredQueryParams, Map<String, String[]> requestParameterMap) {
        List<Matcher> matchingMatchers = new ArrayList<>();
        
        for (QueryParam configuredQueryParam : configuredQueryParams) {
            boolean paramMatchFound = false;
            Pattern configuredKeyPattern = Pattern.compile(configuredQueryParam.getKeyRegex());
            Pattern configuredValuePattern = Pattern.compile(configuredQueryParam.getValueRegex());

            for (Map.Entry<String, String[]> requestParam : requestParameterMap.entrySet()) {
                Matcher keyMatcher = configuredKeyPattern.matcher(decodeQueryString(requestParam.getKey()));

                if (keyMatcher.matches()) {
                    boolean valueMatchFound = false;

                    for (String requestValue : requestParam.getValue()) {
                        Matcher valueMatcher = configuredValuePattern.matcher(decodeQueryString(requestValue));

                        if (valueMatcher.matches()) {
                            matchingMatchers.add(valueMatcher);
                            paramMatchFound = true;
                            valueMatchFound = true;
                        }
                    }

                    if (valueMatchFound) { matchingMatchers.add(keyMatcher); }
                }
            }

            if (!paramMatchFound) { return null; }
        }

        return matchingMatchers;
    }

    private String decodeQueryString(String queryString) {
        String processedQueryString = queryString;

        try {
            processedQueryString = URLDecoder.decode(processedQueryString, "UTF-8");
        } catch (UnsupportedEncodingException uee) {
            /* Since we've hardcoded the UTF-8 encoding, this should never occur. */
            LOG.error("RateLimitingService.decodeQueryString - Unsupported Encoding", uee);
        }

        return processedQueryString;
    }
}
