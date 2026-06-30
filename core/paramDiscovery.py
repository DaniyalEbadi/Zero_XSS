from core.config import blindParams, xsschecker
from core.requester import requester
from core.log import setup_logger

logger = setup_logger(__name__)


def discover_params(url, headers, GET, delay, timeout):
    discovered = {}
    for param in blindParams:
        test_params = {param: xsschecker}
        try:
            response = requester(url, test_params, headers, GET, delay, timeout)
            if xsschecker in response.text:
                discovered[param] = True
                logger.good('Discovered parameter: %s' % param)
        except Exception as e:
            logger.debug('Param discovery error for %s: %s' % (param, str(e)))
    return discovered
