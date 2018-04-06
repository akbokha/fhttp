from PacketHandler.Filters.tcp_regex_filter import TcpRegexFilter


class Http200Filter(TcpRegexFilter):

    def __init__(self):
        super(Http200Filter, self).__init__('^HTTP/\d(\.\d)? 200 OK[^\n]*\r\n[\s\S]*$')
