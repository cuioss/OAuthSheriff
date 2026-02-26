/*
 * Copyright © 2025 CUI-OpenSource-Software (info@cuioss.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.cuioss.sheriff.oauth.quarkus.servlet;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import lombok.Getter;
import lombok.Setter;
import lombok.experimental.Accessors;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.Principal;
import java.util.*;

/**
 * Mock implementation of {@link HttpServletRequest} for testing purposes.
 * 
 * <p>This mock provides simple mutators for header management and implements
 * the most commonly used methods for JWT testing scenarios. Non-implemented
 * methods throw {@link UnsupportedOperationException}.</p>
 * 
 * <p>Usage example:</p>
 * <pre>{@code
 * HttpServletRequestMock mock = new HttpServletRequestMock();
 * mock.setHeader("Authorization", "Bearer token123");
 * mock.addHeader("X-Custom-Header", "value1");
 * mock.addHeader("X-Custom-Header", "value2");
 * 
 * // Use in tests
 * String authHeader = mock.getHeader("Authorization");
 * Enumeration<String> customHeaders = mock.getHeaders("X-Custom-Header");
 * }</pre>
 *
 * @author Oliver Wolff
 */
@Getter
@Setter
@Accessors(chain = true)
public class HttpServletRequestMock implements HttpServletRequest {

    private final Map<String, List<String>> headers = new HashMap<>();
    private final Map<String, Object> attributes = new HashMap<>();
    private final Map<String, String[]> parameters = new HashMap<>();

    private String method = "GET";
    private String requestURI = "/";
    private String contextPath = "";
    private String servletPath = "";
    private String pathInfo = null;
    private String queryString = null;
    private String protocol = "HTTP/1.1";
    private String scheme = "http";
    private String serverName = "localhost";
    private int serverPort = 8080;
    private String remoteAddr = "127.0.0.1";
    private String remoteHost = "localhost";
    private int remotePort = 12345;
    private String localAddr = "127.0.0.1";
    private String localName = "localhost";
    private int localPort = 8080;

    // Header management methods

    /**
     * Sets a header value, replacing any existing values for the same header name.
     * 
     * @param name the header name
     * @param value the header value
     * @return this mock for method chaining
     */
    public HttpServletRequestMock setHeader(String name, String value) {
        List<String> values = new ArrayList<>();
        values.add(value);
        headers.put(name.toLowerCase(Locale.ROOT), values);
        return this;
    }

    /**
     * Adds a header value to the existing values for the given header name.
     * 
     * @param name the header name
     * @param value the header value to add
     * @return this mock for method chaining
     */
    public HttpServletRequestMock addHeader(String name, String value) {
        headers.computeIfAbsent(name.toLowerCase(Locale.ROOT), k -> new ArrayList<>()).add(value);
        return this;
    }

    /**
     * Removes all values for the given header name.
     * 
     * @param name the header name to remove
     * @return this mock for method chaining
     */
    public HttpServletRequestMock removeHeader(String name) {
        headers.remove(name.toLowerCase(Locale.ROOT));
        return this;
    }

    /**
     * Clears all headers.
     * 
     * @return this mock for method chaining
     */
    public HttpServletRequestMock clearHeaders() {
        headers.clear();
        return this;
    }

    /**
     * Sets the Authorization header with a Bearer token.
     * 
     * @param token the bearer token (without "Bearer " prefix)
     * @return this mock for method chaining
     */
    public HttpServletRequestMock setBearerToken(String token) {
        return setHeader("Authorization", "Bearer " + token);
    }

    // Lombok @Getter/@Setter with @Accessors(chain = true) handles the property getters/setters

    // HttpServletRequest implementation

    @Override
    public String getHeader(String name) {
        List<String> values = headers.get(name.toLowerCase(Locale.ROOT));
        return values != null && !values.isEmpty() ? values.getFirst() : null;
    }

    @Override
    public Enumeration<String> getHeaders(String name) {
        List<String> values = headers.get(name.toLowerCase(Locale.ROOT));
        return values != null ? Collections.enumeration(values) : Collections.enumeration(Collections.emptyList());
    }

    @Override
    public Enumeration<String> getHeaderNames() {
        return Collections.enumeration(headers.keySet());
    }

    @Override
    public int getIntHeader(String name) {
        String value = getHeader(name);
        return value != null ? Integer.parseInt(value) : -1;
    }

    @Override
    public long getDateHeader(String name) {
        String value = getHeader(name);
        return value != null ? Long.parseLong(value) : -1;
    }

    // All getter methods are generated by Lombok @Getter

    @Override
    public Object getAttribute(String name) {
        return attributes.get(name);
    }

    @Override
    public void setAttribute(String name, Object value) {
        attributes.put(name, value);
    }

    @Override
    public void removeAttribute(String name) {
        attributes.remove(name);
    }

    @Override
    public Enumeration<String> getAttributeNames() {
        return Collections.enumeration(attributes.keySet());
    }

    @Override
    public String getParameter(String name) {
        String[] values = parameters.get(name);
        return values != null && values.length > 0 ? values[0] : null;
    }

    @Override
    public String[] getParameterValues(String name) {
        return parameters.get(name);
    }

    @Override
    public Enumeration<String> getParameterNames() {
        return Collections.enumeration(parameters.keySet());
    }

    @Override
    public Map<String, String[]> getParameterMap() {
        return Collections.unmodifiableMap(parameters);
    }

    // Unsupported methods - throw UnsupportedOperationException

    @Override
    public String getAuthType() {
        throw new UnsupportedOperationException("getAuthType() not implemented in mock");
    }

    @Override
    public Cookie[] getCookies() {
        throw new UnsupportedOperationException("getCookies() not implemented in mock");
    }

    @Override
    public String getPathTranslated() {
        throw new UnsupportedOperationException("getPathTranslated() not implemented in mock");
    }

    @Override
    public String getRemoteUser() {
        throw new UnsupportedOperationException("getRemoteUser() not implemented in mock");
    }

    @Override
    public boolean isUserInRole(String role) {
        throw new UnsupportedOperationException("isUserInRole() not implemented in mock");
    }

    @Override
    public Principal getUserPrincipal() {
        throw new UnsupportedOperationException("getUserPrincipal() not implemented in mock");
    }

    @Override
    public String getRequestedSessionId() {
        throw new UnsupportedOperationException("getRequestedSessionId() not implemented in mock");
    }

    @Override
    public StringBuffer getRequestURL() {
        throw new UnsupportedOperationException("getRequestURL() not implemented in mock");
    }

    @Override
    public HttpSession getSession(boolean create) {
        throw new UnsupportedOperationException("getSession() not implemented in mock");
    }

    @Override
    public HttpSession getSession() {
        throw new UnsupportedOperationException("getSession() not implemented in mock");
    }

    @Override
    public String changeSessionId() {
        throw new UnsupportedOperationException("changeSessionId() not implemented in mock");
    }

    @Override
    public boolean isRequestedSessionIdValid() {
        throw new UnsupportedOperationException("isRequestedSessionIdValid() not implemented in mock");
    }

    @Override
    public boolean isRequestedSessionIdFromCookie() {
        throw new UnsupportedOperationException("isRequestedSessionIdFromCookie() not implemented in mock");
    }

    @Override
    public boolean isRequestedSessionIdFromURL() {
        throw new UnsupportedOperationException("isRequestedSessionIdFromURL() not implemented in mock");
    }

    @Override
    public boolean authenticate(HttpServletResponse response) throws IOException {
        throw new UnsupportedOperationException("authenticate() not implemented in mock");
    }

    @Override
    public void login(String username, String password) {
        throw new UnsupportedOperationException("login() not implemented in mock");
    }

    @Override
    public void logout() {
        throw new UnsupportedOperationException("logout() not implemented in mock");
    }

    @Override
    public Collection<Part> getParts() {
        throw new UnsupportedOperationException("getParts() not implemented in mock");
    }

    @Override
    public Part getPart(String name) {
        throw new UnsupportedOperationException("getPart() not implemented in mock");
    }

    @Override
    public <T extends HttpUpgradeHandler> T upgrade(Class<T> httpUpgradeHandlerClass) {
        throw new UnsupportedOperationException("upgrade() not implemented in mock");
    }

    @Override
    public String getCharacterEncoding() {
        throw new UnsupportedOperationException("getCharacterEncoding() not implemented in mock");
    }

    @Override
    public void setCharacterEncoding(String env) throws UnsupportedEncodingException {
        throw new UnsupportedOperationException("setCharacterEncoding() not implemented in mock");
    }

    @Override
    public int getContentLength() {
        throw new UnsupportedOperationException("getContentLength() not implemented in mock");
    }

    @Override
    public long getContentLengthLong() {
        throw new UnsupportedOperationException("getContentLengthLong() not implemented in mock");
    }

    @Override
    public String getContentType() {
        throw new UnsupportedOperationException("getContentType() not implemented in mock");
    }

    @Override
    public ServletInputStream getInputStream() {
        throw new UnsupportedOperationException("getInputStream() not implemented in mock");
    }

    @Override
    public BufferedReader getReader() {
        throw new UnsupportedOperationException("getReader() not implemented in mock");
    }

    @Override
    public Locale getLocale() {
        throw new UnsupportedOperationException("getLocale() not implemented in mock");
    }

    @Override
    public Enumeration<Locale> getLocales() {
        throw new UnsupportedOperationException("getLocales() not implemented in mock");
    }

    @Override
    public boolean isSecure() {
        throw new UnsupportedOperationException("isSecure() not implemented in mock");
    }

    @Override
    public RequestDispatcher getRequestDispatcher(String path) {
        throw new UnsupportedOperationException("getRequestDispatcher() not implemented in mock");
    }

    @Override
    public ServletContext getServletContext() {
        throw new UnsupportedOperationException("getServletContext() not implemented in mock");
    }

    @Override
    public AsyncContext startAsync() {
        throw new UnsupportedOperationException("startAsync() not implemented in mock");
    }

    @Override
    public AsyncContext startAsync(ServletRequest servletRequest, ServletResponse servletResponse) {
        throw new UnsupportedOperationException("startAsync() not implemented in mock");
    }

    @Override
    public boolean isAsyncStarted() {
        throw new UnsupportedOperationException("isAsyncStarted() not implemented in mock");
    }

    @Override
    public boolean isAsyncSupported() {
        throw new UnsupportedOperationException("isAsyncSupported() not implemented in mock");
    }

    @Override
    public AsyncContext getAsyncContext() {
        throw new UnsupportedOperationException("getAsyncContext() not implemented in mock");
    }

    @Override
    public DispatcherType getDispatcherType() {
        throw new UnsupportedOperationException("getDispatcherType() not implemented in mock");
    }

    @Override
    public ServletConnection getServletConnection() {
        throw new UnsupportedOperationException("getServletConnection() not implemented in mock");
    }

    @Override
    public String getProtocolRequestId() {
        throw new UnsupportedOperationException("getProtocolRequestId() not implemented in mock");
    }

    @Override
    public String getRequestId() {
        throw new UnsupportedOperationException("getRequestId() not implemented in mock");
    }
}