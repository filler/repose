package org.openrepose.powerfilter.filtercontext;

import com.oracle.javaee6.FilterType;
import com.oracle.javaee6.ParamValueType;

import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

public class FilterConfigWrapper implements FilterConfig {

    private final ServletContext servletContext;
    private final FilterType filterType;
    private final Map<String, String> initParams;
    private final String config;

    public FilterConfigWrapper(ServletContext servletContext, FilterType filterType, String config) {
        if (filterType == null) {
            throw new IllegalArgumentException("filter type cannot be null");
        }
        this.servletContext = servletContext;
        this.filterType = filterType;
        this.config = config;
        initParams = new HashMap<>();

        initParams.put("filter-config", config);

        for (ParamValueType param : filterType.getInitParam()) {
            initParams.put(param.getParamName().getValue(), param.getParamValue().getValue());
        }
    }

    @Override
    public String getFilterName() {
        return filterType.getFilterName().getValue();
    }

    @Override
    public ServletContext getServletContext() {
        return servletContext;
    }

    @Override
    public String getInitParameter(String name) {
        return initParams.get(name);
    }

    @Override
    public Enumeration<String> getInitParameterNames() {
        return Collections.enumeration(initParams.keySet());
    }

    public String getFilterConfig() {
        return config;
    }
}

