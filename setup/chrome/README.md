# Chrome Memory Analysis

Compare Chrome versions 102.0.5005.61 and 133.0.6943.141 during 4K YouTube video streaming.

## How to Run

```bash
# Install Chrome v102.0.5005.61
sudo dpkg -i google-chrome-stable_102.0.5005.61-1_amd64.deb
sudo apt-get install -f

# Install Chrome v133.0.6943.141  
sudo dpkg -i google-chrome-stable_133.0.6943.141-1_amd64.deb
sudo apt-get install -f

# Test with 4K YouTube video streaming
# Navigate to: https://www.youtube.com/watch?v=AjWfY7SnMBI&t=3600s
# Set quality to 4K and play for 1 minute
```