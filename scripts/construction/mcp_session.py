"""Call evidence MCP tools through stdio and retain each request and response."""
import argparse
import asyncio
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


def substitute(value, results):
    if isinstance(value, str) and value.startswith('$result.'):
        parts = value.split('.')[1:]
        current = results[parts[0]]
        for part in parts[1:]:
            current = current[part]
        return current
    if isinstance(value, dict):
        return {key: substitute(item, results) for key, item in value.items()}
    if isinstance(value, list):
        return [substitute(item, results) for item in value]
    return value


async def run(args):
    requests = json.loads(Path(args.requests).read_text())
    destination = Path(args.output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    results = {}
    failed = False
    parameters = StdioServerParameters(command=sys.executable, args=['-m', 'tdn_evidence.server', '--config', str(Path(args.config).resolve())])
    #* Exclusive creation preserves earlier sessions, including failed requests.
    with destination.open('x') as output:
        async with stdio_client(parameters) as (reader, writer):
            async with ClientSession(reader, writer) as session:
                await session.initialize()
                for index, request in enumerate(requests):
                    operation = request.get('operation', 'call_tool')
                    arguments = substitute(request.get('arguments', {}), results)
                    started = datetime.now(timezone.utc).isoformat()
                    try:
                        if operation == 'read_resource':
                            response = await session.read_resource(arguments['uri'])
                        elif operation == 'list_tools':
                            response = await session.list_tools()
                        else:
                            response = await session.call_tool(request['tool'], arguments)
                            if request.get('wait_complete') and not response.isError:
                                collection = response.structuredContent['id']
                                results[request.get('id', str(index))] = response.structuredContent
                                record = {'at': started, 'request': request, 'arguments': arguments, 'response': response.model_dump(mode='json')}
                                output.write(json.dumps(record) + '\n'); output.flush()
                                for _ in range(args.poll_limit):
                                    await asyncio.sleep(1)
                                    response = await session.call_tool('collection_status', {'collection': collection})
                                    record = {'at': datetime.now(timezone.utc).isoformat(), 'request': {'tool': 'collection_status'}, 'arguments': {'collection': collection}, 'response': response.model_dump(mode='json')}
                                    output.write(json.dumps(record) + '\n'); output.flush()
                                    if response.isError or response.structuredContent.get('status') != 'running':
                                        break
                                else:
                                    raise TimeoutError('Collection did not finish within the polling limit')
                        record = {'at': started, 'request': request, 'arguments': arguments, 'response': response.model_dump(mode='json')}
                        results[request.get('id', str(index))] = getattr(response, 'structuredContent', None) or response.model_dump(mode='json')
                    except Exception as error:
                        record = {'at': started, 'request': request, 'arguments': arguments, 'error': str(error)}
                    output.write(json.dumps(record) + '\n')
                    output.flush()
                    failed = failed or bool(record.get('error')) or record.get('response', {}).get('isError', False)
                    print(json.dumps({'index': index, 'tool': request.get('tool', operation), 'error': record.get('error'), 'isError': record.get('response', {}).get('isError', False)}))
    print('Session saved to ' + str(destination))
    if failed:
        raise SystemExit(1)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', required=True)
    parser.add_argument('--requests', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--poll-limit', type=int, default=300)
    asyncio.run(run(parser.parse_args()))


if __name__ == '__main__':
    main()
