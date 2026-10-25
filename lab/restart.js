import http from 'k6/http';
import { check } from 'k6';

export const options = {
  scenarios: {
    restart: {
      executor: 'constant-arrival-rate',
      rate: 20,
      timeUnit: '1s',
      duration: '25s',
      preAllocatedVUs: 10,
      maxVUs: 30,
    },
  },
};

export default function () {
  const response = http.get('http://app.test:8080/health', {
    headers: { 'User-Agent': 'Mozilla/5.0 KunatoLabRestart/1.0' },
  });
  check(response, { 'status is 200': (r) => r.status === 200 });
}
