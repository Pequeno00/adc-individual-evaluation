# ADC-PEI 25/26 — First Web Application (Storage)

This repository is a fork of [https://github.com/ADC-Projeto/adc-pei-2526-part3.git](https://github.com/ADC-Projeto/adc-pei-2526-part3.git)

Building on Part 3, this version introduces:

- Registering users in the database
- Login registered users
- Access login logs

Instead of trying to fork this repository, use your previous fork of the original (part3) repo and add this repository as a new remote:

```
git remote add storage-repo https://github.com/fpb/adc-pei-2526-storage.git
```

Fetch the branches:
```git fetch storage-repo```

Checkout a specific branch, as needed (here with the storage branch as an example):

```
git checkout -b storage storage-repo/storage
```
---
Apart from the **main** branch, which is exactly as it was from the original forked repository, the following branches were added to the repository:

- **storage**: the base branch where to start
- **task-1**: task-1 completed - A first take on registering a new user.
- **task-2**: task-2 completed - A robust implementation of user registration.
- **task-3**: task-3 completed - A login with logging records.
- **task-4**: task-4 completed - A service to retrieve the last logins of a user
- **task-5**: task-5 completed - Same as task-4 but with pagination.
- **task-6**: task-6 completed - A more sophisticated login request with ip and location 
- **task-7**: task-7 completed. Cloud storage example.

The branches follow a linear timeline with each one building on the previous:

```
main -> storage -> task-1 -> task-2 > ... -> task-6 -> cloud-storage.
```

Please follow the slides as you go along.

---

## License

See [LICENSE](LICENSE) for details.

---

*FCT NOVA — ADC-PEI 2025/2026*
