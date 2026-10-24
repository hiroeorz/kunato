import http from 'k6/http';
import { check } from 'k6';

export const options = {
  scenarios: {
    steady: {
      executor: 'constant-arrival-rate',
      rate: 50,
      timeUnit: '1s',
      duration: '60s',
      preAllocatedVUs: 10,
      maxVUs: 20,
    },
  },
  thresholds: {
    http_req_failed: ['rate<0.01'],
    http_req_duration: ['p(95)<200', 'p(99)<500'],
    checks: ['rate>0.99'],
  },
};

export default function () {
  const response = http.get('http://app.test:8080/load', {
    headers: { 'User-Agent': 'Mozilla/5.0 KunatoLabLoad/1.0' },
  });
  check(response, { 'status is 200': (r) => r.status === 200 });
}
