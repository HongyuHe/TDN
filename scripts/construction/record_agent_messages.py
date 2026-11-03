"""Preserve agent-call transport records without claiming protected text is readable."""
import argparse
import datetime
import json
from pathlib import Path
import re


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--session',type=Path,required=True)
    parser.add_argument('--since',required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    records=[]
    for line in args.session.open():
        record=json.loads(line)
        if str(record.get('timestamp','')) < args.since:
            continue
        payload=record.get('payload',{})
        if payload.get('type')!='function_call' or payload.get('namespace')!='collaboration' or payload.get('name') not in ['spawn_agent','send_message','followup_task','interrupt_agent']:
            continue
        arguments=payload.get('arguments',{})
        if isinstance(arguments,str):arguments=json.loads(arguments)
        message = arguments.get('message')
        protected = isinstance(message, str) and re.fullmatch(r'gAAAAA[A-Za-z0-9_=-]{70,}', message) is not None
        records.append({'at':record['timestamp'],'operation':payload['name'],'call_id':payload.get('call_id'),'arguments':arguments,
                        'message_storage': 'protected_transport' if protected else 'plain_text',
                        'readable_message': not protected})
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open('x') as output:
        for record in records:output.write(json.dumps(record,ensure_ascii=False)+'\n')
    print(json.dumps({'records':len(records),'protected_messages':sum(not row['readable_message'] for row in records),
                      'output':str(args.output),'at':datetime.datetime.now(datetime.timezone.utc).isoformat()}))


if __name__=='__main__':main()
