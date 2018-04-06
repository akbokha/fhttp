from PacketHandler.Filters.tcp_regex_filter import TcpRegexFilter


class HttpRequestFilter(TcpRegexFilter):

    def __init__(self):
        super(HttpRequestFilter, self).__init__('^GET [^\n]* HTTP/\d(\.\d)?[^\n]*\r\n[\s\S]*$')
